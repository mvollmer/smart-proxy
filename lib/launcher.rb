require 'proxy/log'
require 'proxy/sd_notify'
require 'proxy/settings'
require 'proxy/signal_handler'
require 'proxy/log_buffer/trace_decorator'
require 'thread'
require 'rack'
require 'webrick'

module Proxy
  class Launcher
    include ::Proxy::Log

    attr_reader :settings

    def initialize(settings = SETTINGS)
      @settings = settings
      @settings.http_server_type = Proxy::SETTINGS.http_server_type.to_sym
      if @settings.http_server_type == :puma
        begin
          require 'puma'
          require 'rack/handler/puma'
          require 'puma-patch'
        rescue LoadError
          logger.warn 'Puma was requested but not installed, falling back to webrick'
          @settings.http_server_type = :webrick
        end
      end
      @servers = []
    end

    def pid_path
      @settings.daemon_pid
    end

    def http_enabled?
      !@settings.http_port.nil?
    end

    def https_enabled?
      @settings.ssl_private_key && @settings.ssl_certificate && @settings.ssl_ca_file
    end

    def plugins
      ::Proxy::Plugins.instance.select { |p| p[:state] == :running }
    end

    def http_plugins
      plugins.select { |p| p[:http_enabled] }.map { |p| p[:class] }
    end

    def https_plugins
      plugins.select { |p| p[:https_enabled] }.map { |p| p[:class] }
    end

    def http_app(http_port, plugins = http_plugins)
      return nil unless http_enabled?
      app = Rack::Builder.new do
        plugins.each { |p| instance_eval(p.http_rackup) }
      end

      {
        :app => app,
        :server => @settings.http_server_type,
        :DoNotListen => true,
        :Port => http_port, # only being used to correctly log http port being used
        :Logger => ::Proxy::LogBuffer::TraceDecorator.instance,
        :AccessLog => [],
        :ServerSoftware => "foreman-proxy/#{Proxy::VERSION}",
        :daemonize => false
      }
    end

    def https_app(https_port, plugins = https_plugins)
      unless https_enabled?
        logger.warn "Missing SSL setup, https is disabled."
        return nil
      end

      app = Rack::Builder.new do
        plugins.each { |p| instance_eval(p.https_rackup) }
      end

      ssl_options = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options]
      ssl_options |= OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE if defined?(OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE)
      # This is required to disable SSLv3 on Ruby 1.8.7
      ssl_options |= OpenSSL::SSL::OP_NO_SSLv2 if defined?(OpenSSL::SSL::OP_NO_SSLv2)
      ssl_options |= OpenSSL::SSL::OP_NO_SSLv3 if defined?(OpenSSL::SSL::OP_NO_SSLv3)
      ssl_options |= OpenSSL::SSL::OP_NO_TLSv1 if defined?(OpenSSL::SSL::OP_NO_TLSv1)

      if @settings.tls_disabled_versions
        @settings.tls_disabled_versions.each do |version|
          constant = OpenSSL::SSL.const_get("OP_NO_TLSv#{version.to_s.tr('.', '_')}") rescue nil

          if constant
            logger.info "TLSv#{version} will be disabled."
            ssl_options |= constant
          else
            logger.warn "TLSv#{version} was not found."
          end
        end
      end

      app_details = {
        :app => app,
        :server => @settings.http_server_type,
        :DoNotListen => true,
        :Port => https_port, # only being used to correctly log https port being used
        :Logger => ::Proxy::LogBuffer::Decorator.instance,
        :ServerSoftware => "foreman-proxy/#{Proxy::VERSION}",
        :SSLEnable => true,
        :SSLVerifyClient => OpenSSL::SSL::VERIFY_PEER,
        :SSLCACertificateFile => @settings.ssl_ca_file,
        :SSLOptions => ssl_options,
        :daemonize => false
      }
      case @settings.http_server_type
      when :webrick
        app_details[:SSLPrivateKey] = load_ssl_private_key(@settings.ssl_private_key)
        app_details[:SSLCertificate] = load_ssl_certificate(@settings.ssl_certificate)
      when :puma
        app_details[:SSLArgs] = {
          :ca => @settings.ssl_ca_file,
          :key => @settings.ssl_private_key,
          :cert => @settings.ssl_certificate
        }
      end
      app_details
    end

    def load_ssl_private_key(path)
      OpenSSL::PKey::RSA.new(File.read(path))
    rescue Exception => e
      logger.error "Unable to load private SSL key. Are the values correct in settings.yml and do permissions allow reading?", e
      raise e
    end

    def load_ssl_certificate(path)
      OpenSSL::X509::Certificate.new(File.read(path))
    rescue Exception => e
      logger.error "Unable to load SSL certificate. Are the values correct in settings.yml and do permissions allow reading?", e
      raise e
    end

    def pid_status
      return :exited unless File.exist?(pid_path)
      pid = ::File.read(pid_path).to_i
      return :dead if pid == 0
      Process.kill(0, pid)
      :running
    rescue Errno::ESRCH
      :dead
    rescue Errno::EPERM
      :not_owned
    end

    def check_pid
      case pid_status
      when :running, :not_owned
        logger.error "A server is already running. Check #{pid_path}"
        exit(2)
      when :dead
        File.delete(pid_path)
      end
    end

    def write_pid
      FileUtils.mkdir_p(File.dirname(pid_path)) unless File.exist?(pid_path)
      File.open(pid_path, ::File::CREAT | ::File::EXCL | ::File::WRONLY){|f| f.write(Process.pid.to_s) }
      at_exit { File.delete(pid_path) if File.exist?(pid_path) }
    rescue Errno::EEXIST
      check_pid
      retry
    end

    def add_puma_server(app, address, port, conn_type)
      logger.debug "Launching Puma listener at #{address} port #{port}"
      if conn_type == :ssl
        require 'cgi'
        query_list = app[:SSLArgs].to_a.map do |x|
          "#{CGI::escape(x[0].to_s)}=#{CGI::escape(x[1])}"
        end
        host = "ssl://#{address}/?#{query_list.join('&')}"
      else
        host = address
      end
      logger.debug "Host URL: #{host}"
      # the following lines are from lib/rack/handler/puma.rb#run
      options = {Verbose: true, Port: port, Host: host}
      conf = Rack::Handler::Puma.config(app[:app], options)
      events = ::Puma::Events.new(::Proxy::LogBuffer::Decorator.instance, ::Proxy::LogBuffer::Decorator.instance)
      launcher = ::Puma::Launcher.new(conf, :events => events)
      @servers << launcher
      launcher.run
    end

    def add_webrick_server(app, addresses, port)
      server = ::WEBrick::HTTPServer.new(app)
      addresses.each do |address|
        logger.debug "Launching Webrick listener at #{address} port #{port}"
        server.listen(address, port)
      end
      server.mount '/', Rack::Handler::WEBrick, app[:app]
      server
    end

    def add_threaded_server(server_name, conn_type, app, addresses, port)
      result = []
      case server_name
      when :webrick
        result << Thread.new do
          @servers << add_webrick_server(app, addresses, port).start
        end
      when :puma
        addresses.map{|a| a == '*' ? ['0.0.0.0', '[::1]'] : a}.flatten.each do |address|
          result << Thread.new do
            add_puma_server(app, address, port, conn_type)
          end
        end
      end
      result
    end

    def launch
      raise Exception.new("Both http and https are disabled, unable to start.") unless http_enabled? || https_enabled?

      if @settings.daemon
        check_pid
        Process.daemon
        write_pid
      end

      ::Proxy::PluginInitializer.new(::Proxy::Plugins.instance).initialize_plugins

      http_app = http_app(@settings.http_port)
      https_app = https_app(@settings.https_port)
      install_http_server_callback!(http_app, https_app)

      http_server_name = @settings.http_server_type
      https_server_name = @settings.http_server_type
      threads = []
      if https_app
        threads += add_threaded_server(https_server_name,
                                 :ssl,
                                 https_app,
                                 @settings.bind_host,
                                 @settings.https_port)
      end

      if http_app
        threads += add_threaded_server(http_server_name,
                                 :tcp,
                                 http_app,
                                 @settings.bind_host,
                                 @settings.http_port)
      end

      Proxy::SignalHandler.install_traps(@servers)
      threads.each(&:join)
    rescue SignalException => e
      logger.debug("Caught #{e}. Exiting")
      raise
    rescue SystemExit
      # do nothing. This is to prevent the exception handler below from catching SystemExit exceptions.
      raise
    rescue Exception => e
      logger.error "Error during startup, terminating", e
      puts "Errors detected on startup, see log for details. Exiting: #{e}"
      exit(1)
    end

    def install_http_server_callback!(*apps)
      apps.compact!

      # track how many apps are still starting up
      @pending_server = apps.size
      @pending_server_lock = Mutex.new

      apps.each do |app|
        # add a callback to each server, decrementing the pending counter
        app[:StartCallback] = lambda do
          @pending_server_lock.synchronize do
            @pending_server -= 1
            launched(apps) if @pending_server.zero?
          end
        end
      end
    end

    def launched(apps)
      logger.info("Smart proxy has launched on #{apps.size} socket(s), waiting for requests")
      Proxy::SdNotify.new.tap { |sd| sd.ready if sd.active? }
    end
  end
end
