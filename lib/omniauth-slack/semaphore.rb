require 'omniauth-slack/refinements'

module OmniAuth
  module Slack
    using ObjectRefinements
    
    ### Prepend Semaphore module to get simple mutexes for each/any method.

    module Semaphore    
      def initialize(*args)
        super
        @main_semaphore = Mutex.new
        @semaphores = {}
      end
      
      # Get a mutex specific to the calling method.
      # This operation is synchronized with its own mutex.
      #def semaphore(method_name = caller[0][CALLER_NAME_REGEXP])
      def semaphore(method_name = caller_method_name)
        #OmniAuth.logger.debug "#{self.class}##{object_id} synchronizing method #{method_name}."
        @main_semaphore.synchronize {
          @semaphores[method_name] ||= Mutex.new
        }
      end
      
    end # Semaphore
  end # Slack
end # OmniAuth