require 'hashie'

module OmniAuth
  module Slack
  
    class Hashy < Hashie::Hash
      include Hashie::Extensions::MergeInitializer
      include Hashie::Extensions::MethodReader
      include Hashie::Extensions::MethodQuery
      include Hashie::Extensions::IndifferentAccess
    end
    
    class Mashy < Hashie::Mash
    end


    # Include DataMethods module in your OmniAuth::Strategy class
    # to gain flexible method dependency management.

    module DataMethods
          
      def self.included(other)
        #OmniAuth.logger.log(0, "#{other} included #{self}")
        other.instance_eval do
          extend Extensions
          singleton_class.send :attr_reader, :data_methods
          @data_methods ||= Hashy.new
          option :dependencies, nil
        end
      end
            
      def dependencies
        options.dependencies || @dependencies ||= self.class.dependencies.keys
      end
      
      def data_methods; self.class.data_methods; end
      
      # TODO: Consider getting rid of this, or at least not using it for build-in omniauth-slack 'info' keys/values.
      #       But keep it around for user-defined data methods that should be attached to the info hash.
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


      module Extensions

        # List DataMethod instances and their dependencies.
        def dependency_tree
          result = Hashy.new
          data_methods.each do |key, val|
            #puts "DataMethods::Extensions.dependencies, data_methods.each, key '#{key}' val-type '#{val.class}'"
            result[key] = val.source.to_a.map{|s| s[:name].to_s}
          end
          result
        end

        # Flatten compiled dependency_tree into an array of uniq strings.
        def dependencies
          #dependency_tree.map{|k,v| v}.flatten(-1).inject([]){|a,v| a << v.to_s; a}.uniq
          deps = dependency_tree.map{|k,v| v}.flatten(-1).inject([]){|a,v| a << v.to_s; a}
          deps.inject({}){|h, v| h[v] ? h[v] +=1 : h[v] = 1; h}
        end  
        
        # Which dependencies are missing callable methods.
        def missing_dependencies
          dependencies.keys.select{|m| !method_defined?(m) && !private_method_defined?(m)}
        end 
        
        # Build a DataMethod object from a hash or a block.
        def data_method(name, opts = Hashy.new)
          
          #OmniAuth.logger.log(0, "(slack) Building data_method object (#{name}, #{opts})")
          data_methods[name] = case
            when block_given?
              DataMethod.new(name, opts, &Proc.new)  #opts.merge!(name: name)
            else
              DataMethod.new(name, opts)  #opts.merge!(name: name)
          end
          
          define_method(name) do
            method_opts = data_methods[__method__]
            storage_name = method_opts[:storage] || name
            
            semaphore(name).synchronize do
              case
              when ivar_data = instance_variable_get("@#{storage_name}")
                #log(:debug, "Data method '#{name}' returning stored value: #{ivar_data}.")
                #return ivar_data
                result = ivar_data
            
              when (
                #log(:debug, "Data method '#{name}' asking has_scope? with '#{method_opts[:scope]}' and opts '#{method_opts[:scope_opts]}'")
                #(scopes = method_opts[:scope]) && !has_scope?(scopes, method_opts[:scope_opts]) ||
                (scopes = method_opts[:scope]) && scopes.any? && !has_scope?(scopes, method_opts[:scope_opts]) ||
                (conditions = method_opts[:condition]) && !(conditions.is_a?(Proc) ? conditions.call : eval(conditions))
              )
                #log(:debug, "Data method '#{name}' returning from unmet scopes or conditions.")
                #result = method_opts[:default_value]
                result = nil  # see below
              else
                
                #puts "Data method '#{name}' succeeded scopes & conditions."
                result = nil
                dependencies.keys.each do |apim|
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
                  
                  #puts "Data method '#{name}' end of dependencies loop '#{apim}': #{result.class}"
                  break if result
                end # dependencies.each
                
              end # case
              
              result ||= method_opts[:default_value]
              #log(:debug, "Data method '#{name}' returning: #{result}")
              instance_variable_set(("@#{storage_name}"), result) if result && storage_name && method_opts[:storage] != false
              result
              
            end # semaphore.synchronize
          end # define_method
          
          data_methods[name]
        end # data_method
      end # Extensions
    end # DataMethods



    #####  DataMethod Class  #####

    class DataMethod < Hashy
      #include Hashie::Extensions::StrictKeyAccess
      #include Hashie::Extensions::MethodAccessWithOverride
            
      def self.new(*args)
        opts = Mashy.new(args.last.is_a?(Hash) ? args.pop : {})
        name = args[0].to_s
        setup_block  = Proc.new if block_given?
        new_object = allocate
        %w(name scope scope_opts condition source storage default_value setup_block info_key).each do |property|
          new_object[property] = nil
        end
        new_object[:name] = name if name
        new_object[:setup_block] = setup_block if setup_block
        new_object.merge!(opts)
        new_object.send(:initialize, opts, &setup_block)
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
        return self[__method__] unless args.any?
        self[:scope] ||= []
        #OmniAuth.logger.log(0, "(slack) DataMethod 'scope' with (#{opts})")
        query = args.shift
        opts = args.last
        self[:scope_opts] = opts if opts
        self[:scope] << query
        self[:scope].flatten!
      end
      
      def scope_opts(opts={})
        return self[__method__] unless opts && opts.any?
        self[:scope_opts] = opts
      end
      
      def source(name = nil, opts = Mashy.new)
        return self[__method__] unless name
        self[:source] ||= Hashie::Array.new
        prc = block_given? ? Proc.new : nil
        #OmniAuth.logger.log(0, "(slack) DataMethod 'source' with (#{name}, #{opts}, #{prc})")
        source_hash = Mashy.new({name: name}.merge(opts))
        source_hash[:code] = prc if prc
        self[:source] << source_hash
      end
      
      def storage(arg = nil)
        return self[__method__] unless arg
        #OmniAuth.logger.log(0, "(slack) DataMethod 'storage with (#{arg})")
        self[:storage] = arg
      end
      
      def condition(code = nil)
        return self[__method__] unless code
        self[:condition] ||= []
        code = block_given? ? Proc.new : code
        #OmniAuth.logger.log(0, "(slack) DataMethod 'condition' with (#{code})")
        self[:condition] << code
      end
      
      def default_value(arg = nil)
        return self[__method__] unless arg
        #OmniAuth.logger.log(0, "(slack) DataMethod 'default_value' with (#{arg})")
        self[:default_value] = arg
      end
    end # DataMethod
  
  end # Slack
end # OmniAuth

