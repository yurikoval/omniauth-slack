require 'hashie'
require 'omniauth/strategies/oauth2'
require 'omniauth/auth_hash'

# require 'omniauth-slack/oauth2/client'

# Refinements will work as long as the call to the refined method is lexically scoped with the 'using'.

module OmniAuth
  module Slack
        
    # Why is this here? We can just override the method in Strategy.
    # module OmniAuthRefinements
    #   refine OmniAuth::Strategies::OAuth2 do
    #     def client
    #       OmniAuth::Slack::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
    #     end
    #   end
    # end
      
    module OAuth2Refinements
      refine OAuth2::Response do
        def to_auth_hash
          OmniAuth::Slack::AuthHash.new(parsed)
        end
      end
    end

    # Don't need this either... just subclass the AuthHash in Strategy.
    # module AuthHashRefinements
    #   refine OmniAuth::AuthHash do
    #     include Hashie::Extensions::DeepFind
    #   end
    # end

    module ArrayRefinements
      refine ::Array do
        # Sort this array according to other-array's current order.
        # See https://stackoverflow.com/questions/44536537/sort-the-array-with-reference-to-another-array
        # This also handles items not in the reference_array.
        # Pass :beginning or :ending as the 2nd arg to specify where to put unmatched source items.
        # Pass a block to specify exactly which part of source value is being used for sort.
        # Example: sources.sort_with(dependencies){|v| v.name.to_s}
        def sort_with(reference_array, unmatched = :beginning)
          ref_index = reference_array.to_a.each_with_index.to_h
          unmatched_destination = case unmatched
          when /begin/; -1
          when /end/; 1
          when Integer; unmatched
          else -1
          end
          #puts "Sorting array #{self} with unmatched_destination '#{unmatched_destination}' and reference index #{ref_index}"
          sort_by do |v|
            val = block_given? ? yield(v) : v
            [ref_index[val] || (unmatched_destination * reference_array.size), val]
          end
        end
      end
    end
    
    # module IncludedMethods
    #   def test
    #     puts "This method is defined in a module and included in a String refinement!"
    #   end
    # end
    # 
    # module StringRefinements
    #   refine String do
    #     include IncludedMethods
    #   end
    # end
      
  end # Slack
end # OmniAuth

