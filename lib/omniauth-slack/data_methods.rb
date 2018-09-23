require 'hashie'

module OmniAuth
  module Slack
  
    class Hashy < Hash
      include Hashie::Extensions::MergeInitializer
      include Hashie::Extensions::MethodAccess
      include Hashie::Extensions::IndifferentAccess    
    end
  
    module DataMethods
          
      def self.included(other)
        #OmniAuth.logger.log(0, "#{other} included #{self}")
        other.instance_eval do
          extend Extensions
          singleton_class.send :attr_reader, :data_methods, :api_methods
          # When all data_method dependencies are built with 'data_method' macro, this can go away.
          #@api_methods = %i(access_token identity api_users_identity user_identity user_info user_profile team_identity team_info bot_info)
          @api_methods = Array.new
          @data_methods ||= Hashy.new
        end
      end
    
      module Extensions
      
        # def api_methods(*args)
        #   args.any? ? @api_methods=args : @api_methods
        # end
        
        # List data-methods and their dependencies.
        def dependencies
          result = Hashy.new
          data_methods.each do |key, val|
            #puts "DataMethods::Extensions.dependencies, data_methods.each, key '#{key}' val-type '#{val.class}'"
            result[key] = val.source.to_a.map{|s| s[:name]}
          end
          result
        end

        # Flatten all dependencies to an array of uniq strings.
        def dependencies_flat
          dependencies.map{|k,v| v}.flatten(-1).inject([]){|a,v| a << v.to_s; a}.uniq
        end  
        
        # Which dependencies are missing callable methods.
        def missing_dependencies
          dependencies_flat.select{|m| !method_defined?(m) && !private_method_defined?(m)}
        end 
             
        def data_method(name, opts = Hashy.new)
          #OmniAuth.logger.log(0, "(slack) Calling data_method(#{name}, #{opts})")
          data_methods[name] = case
            when block_given?
              DataMethod.new(name, opts, &Proc.new)  #opts.merge!(name: name)
            else
              DataMethod.new(name, opts)  #opts.merge!(name: name)
          end
          
          # TEMP:
          #return data_methods[name] 
          
          define_method(name) do
            method_opts = data_methods[__method__]
            storage_name = method_opts[:storage] || name
            
            semaphore(name).synchronize do
            
              if ivar_data = instance_variable_get("@#{storage_name}")
                #log(:debug, "Data method '#{name}' returning stored value: #{ivar_data}.")
                return ivar_data
              else
                #log(:debug, "Data method '#{name}' computing value.")
              end
            
              log(:debug, "Data method '#{name}' asking has_scope? with '#{method_opts[:scope]}' and opts '#{method_opts[:scope_opts]}'")
              if (
                #(scopes = method_opts[:scope]) && !has_scope?(scopes, method_opts[:scope_opts]) ||
                (scopes = method_opts[:scope]) && !has_scope?(scopes, method_opts[:scope_opts]) ||
                (conditions = method_opts[:condition]) && !(conditions.is_a?(Proc) ? conditions.call : eval(conditions))
              )
                #log(:debug, "Data method '#{name}' returning from unmet scopes or conditions.")
                return method_opts[:default_value]
              end
              
              #puts "Data method '#{name}' succeeded scopes & conditions."
              result = nil
              api_methods.each do |apim|
                sources = method_opts[:source].select{|h| h[:name].to_s == apim.to_s}
                #puts "Data method '#{name}' with api_method '#{apim}'"
                sources.each do |source|
                  #puts "Processing source for '#{name}': #{source}"
                  source_method = source[:name]
                  source_code = source[:code]
                  method_result = send source_method
                  #puts "Data method '#{name}' with source_method '#{source_method}': #{method_result.class}"
                  
                  if method_result
                    result = case
                      when source_code.is_a?(Proc)
                        method_result.instance_eval(&source_code)
                      when source_code.is_a?(String)
                        method_result.send(:eval, source_code)
                      when source_code.nil?
                        method_result
                      else
                        nil
                    end
                  end # if
                  
                  #puts "Data method '#{name}' end of source loop '#{source}': #{result.class}"
                  break if result
                end # sources.each
                
                #puts "Data method '#{name}' end of api_methods loop '#{apim}': #{result.class}"
                break if result
              end # api_methods.each
              
              result ||= method_opts[:default_value]
              #log(:debug, "Data method '#{name}' returning: #{result}")
              instance_variable_set(("@#{storage_name}"), result) if result && storage_name && method_opts[:storage] != false
              result
              
            end # synchronize
          end # define_method
          
          data_methods[name]
        end # data_method
      end # Extensions
      
      
      def api_methods
        mm = options.api_methods && mm.to_a.any? && mm ||
        self.class.api_methods
      end
      
      def data_methods; self.class.data_methods; end
      
      def apply_data_methods(rslt = Hashy.new)
        data_methods.each do |name, opts|
          key = opts[:info_key]
          #log(:debug, "Applying key '#{key}' with method '#{name}'")
          next unless key
          rslt[key] ||= send(name)
          #log(:debug, "Applying key '#{key}' with method '#{name}': #{rslt[key]}")
          rslt
        end
      end
    
    end # DataMethods


    class DataMethod < Hashy
      
      def self.new(*args)
        opts = args.last.is_a?(Hash) ? args.pop : Hashy.new
        name = args[0]
        prc  = Proc.new if block_given?
        new_object = allocate
        new_object[:name] = name if name
        new_object[:prc] = prc if prc
        new_object.merge!(opts)
        new_object.send(:initialize, opts, &prc)
        new_object
      end
      
      def initialize(opts = Hashy.new)
        OmniAuth.logger.log(0, "(slack) Initialize DataMethod #{self.name}.")
        instance_eval &Proc.new if block_given?
      end
      
      # Expects same args as AccessToken#has_scope?
      #   query == hash or array of hashes
      #   opts (options) == hash of options
      def scope(*args)
        return super unless args.any?
        self[:scope] ||= []
        #OmniAuth.logger.log(0, "(slack) DataMethod 'scope' with (#{opts})")
        #self[:scope] << scope_query.flatten
        #self[:scope].flatten!
        query = args.shift
        opts = args.last
        self[:scope_opts] = opts if opts
        self[:scope] << query
        self[:scope].flatten!
      end
      
      def scope_opts(opts={})
        return super unless opts && opts.any?
        self[:scope_opts] = opts
      end
      
      def source(name = nil, opts = Hashy.new)
        return super unless name
        self[:source] ||= []
        prc = block_given? ? Proc.new : nil
        #OmniAuth.logger.log(0, "(slack) DataMethod 'source' with (#{name}, #{opts}, #{prc})")
        source_hash = Hashy.new({name: name}.merge(opts))
        source_hash[:code] = prc if prc
        self[:source] << source_hash
      end
      
      def storage(arg = nil)
        return super unless arg
        #OmniAuth.logger.log(0, "(slack) DataMethod 'storage with (#{arg})")
        self[:storage] = arg
      end
      
      def condition(code = nil)
        return super unless code
        self[:condition] ||= []
        code = block_given? ? Proc.new : code
        #OmniAuth.logger.log(0, "(slack) DataMethod 'condition' with (#{code})")
        self[:condition] << code
      end
      
      def default_value(arg)
        #OmniAuth.logger.log(0, "(slack) DataMethod 'default_value' with (#{arg})")
        self[:default_value] = arg
      end
    end # DataMethod
  
  end # Slack
end # OmniAuth

