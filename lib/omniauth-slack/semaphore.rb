module OmniAuth
  module Slack
    module Semaphore
    
      def initialize(*args)
        super
        @main_semaphore = Mutex.new
        @semaphores = {}
      end
      
      # Get a mutex specific to the calling method.
      # This operation is synchronized with its own mutex.
      def semaphore(method_name = caller[0][/`([^']*)'/, 1])
        #OmniAuth.logger.debug "#{self} synchronizing method #{method_name}."
        @main_semaphore.synchronize {
          @semaphores[method_name] ||= Mutex.new
        }
      end
      
    end # Semaphore
  end # Slack
end # OmniAuth