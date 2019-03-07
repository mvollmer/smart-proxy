require 'socket'
require 'monitor'

# Implementation of libsystemd's sd_notify API, sends current state via socket
module Proxy
  class SdNotify
    def initialize
      @pending = @total = 1
      @pending_and_total_lock = Monitor.new
    end

    def active?
      !ENV['NOTIFY_SOCKET'].nil?
    end

    def notify(message)
      create_socket.tap do |socket|
        socket.sendmsg(message.chomp + "\n") # ensure trailing \n
        socket.close
      end
    rescue Exception => e
      raise "NOTIFY_SOCKET was set but unable to open: #{e}"
    end

    def ready(state = 1)
      notify("READY=#{state}")
    end

    # schedule ready call after total number of 'ready_all' calls is done
    def ready_when(new_total_number)
      @pending_and_total_lock.synchronize do
        @pending = @total = new_total_number
      end
    end

    # when number of calls matches what was set via 'ready_when' this calls 'ready(state)' method
    # and optional block is executed
    def ready_all(state = 1)
      @pending_and_total_lock.synchronize do
        @pending -= 1
        if active? && @pending.zero?
          yield if block_given?
          ready(state)
        end
      end
    end

    def total
      @pending_and_total_lock.synchronize do
        @total
      end
    end

    def pending
      @pending_and_total_lock.synchronize do
        @pending
      end
    end

    private

    def create_socket
      raise 'Missing NOTIFY_SOCKET environment variable, is this process running under systemd?' unless active?
      Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0).tap do |socket|
        socket.connect(Socket.pack_sockaddr_un(ENV['NOTIFY_SOCKET']))
      end
    end
  end
end
