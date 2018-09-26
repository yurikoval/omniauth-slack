require 'hashie'
require 'omniauth'

module RefineArray
  refine Array do
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

using RefineArray

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

    # DataMethods: declarative method dependency management.
    # 
    # - Get the most data from the fewest API calls.
    # - Assign data gateway priority for methods that can pull from multiple gateways.
    # - Skip a descendant path traversal now, when you know the end point is going to be blocked/down.
    #
    # Include DataMethods module in your OmniAuth::Strategy class
    # to gain flexible method dependency management.
    # Control which data_methods get called and in what priority
    # with the provider block option 'dependencies':
    #
    #   provider ...
    #     dependencies 'my_api_method', 'another_api_method'
    #   end
    #
    # Example data-method declaration in the Strategy class:
    #
    # data_method :my_api_method do
    #   scope classic:'identity.basic', identity:'identity:read:user'
    #   scope team:'conversations:read', app_home:'chat:write'
    #   scope_logic: 'or'  # override the default logic (or) within each scope query.
    #   storage true  # override the name of the cache variable. default is method-name. false disables cache for this method.
    #   condition proc{ true }
    #   condition proc{ ! false }
    #   default_value Hash.new
    #   source :access_token do
    #     get('/api/users.identity', headers: {'X-Slack-User' => user_id}).parsed
    #   end
    # end
    #
    # data_method :user_name do
    #   source :my_api_method do
    #     user.name
    #   end
    # end

    module DataMethods
          
      def self.included(other)
        #OmniAuth.logger.log(0, "#{other} included #{self}")
        other.instance_eval do
          extend Extensions
          singleton_class.send :attr_reader, :data_methods
          @data_methods ||= Hashy.new
          if self.is_a? OmniAuth::Strategy
            option :dependencies, nil  # <string,or,array,of,strings>
            option :dependency_filter  #, /.*/  # will be this /^api_/ when all data-methods & dependencies are properly declared.
          end
        end
      end
      
      # Strategy instance dependencies.
      def dependencies(filter=nil)
        # If you provide a filter, this will return the master dependency list (filtered).
        # Otherwise return the user-defined dependencies, or the class-level deps with the user (or default) filter applied.
        raw = if !filter.nil?
          self.class.dependencies(filter).keys
        else
          options.dependencies || @dependencies ||= self.class.dependencies(dependency_filter).keys
        end
        
        case raw
        when String; eval(raw)
        when Proc; instance_eval(&raw)
        else raw
        end
      end
      
      def dependency_filter
        options.dependency_filter
      end
      
      def data_methods; self.class.data_methods; end
      
      # TODO: Consider getting rid of this, or at least not using it for built-in omniauth-slack 'info' keys/values.
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
      
        # TODO: Temp for debugging
        def sort_with(a1, a2, unmatched=:beginning)
          prc = Proc.new if block_given?
          a1.sort_with(a2, unmatched, &prc)
        end

        # List DataMethod instances and their dependencies.
        def dependency_tree
          data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.dependency_hash; h}
        end

        # Strategy class dependencies.
        # Flattens compiled dependency_tree into an array of uniq strings.
        # TODO: I think this can be cleaned up.
        def dependencies(filter = nil)  #default_options.dependency_filter)
          filter ||= /.*/
          dtree = dependency_tree
          deps  = dtree.values.inject([]){|ary,hsh| ary.concat hsh.keys}
          # TODO: Do we still need this meths list?
          meths = dtree.keys.select(){|k| k.to_s[filter]}
          both = (deps.uniq | meths).sort_with(dtree.keys)
          #puts({deps: deps, meths: meths, both: both}.to_yaml)
          both.inject({}){|h, v| h[v] = deps.count(v.to_s); h}.select{|k,v| k[filter]}
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
              DataMethod.new(name, self, opts, &Proc.new)  #opts.merge!(name: name)
            else
              DataMethod.new(name, self, opts)  #opts.merge!(name: name)
          end
          
          define_method(name) do
            method_opts = data_methods[__method__]
            storage_name = method_opts[:storage] || name
            
            semaphore(name).synchronize do
              case
              when ivar_data = instance_variable_get("@#{storage_name}")
                #log(:debug, "Data method '#{name}' returning stored value: #{ivar_data}.")
                result = ivar_data
              when (
                #log(:debug, "Data method '#{name}' asking has_scope? with '#{method_opts[:scope]}' and opts '#{method_opts[:scope_opts]}'")
                # If scopes don't pass.
                (scopes = method_opts[:scope]) && scopes.any? && !has_scope?(scopes, method_opts[:scope_opts]) ||
                # If conditions don't pass.
                (conditions = method_opts[:condition]) && !(conditions.is_a?(Proc) ? conditions.call : eval(conditions)) #||
              )
                #log :debug, "Data method '#{name}' returning from unmet scopes or conditions."
                result = nil  # see below
              else
                #log :debug, "Data method '#{name}' succeeded scopes & conditions."
                result = nil
                
                sources = method_opts.source.select do |src|
                  dependencies.include?(src.name.to_s) || !dependencies(dependency_filter).include?(src.name.to_s)
                end.sort_with(dependencies){|v| v[:name].to_s}
                #log(:debug, "Data method '#{name}' with selected sources: #{sources.map{|s| s.name}}") if sources.any?
                sources.each do |source|
                  #log :debug, "Processing source for data-method '#{name}': #{source}"
                  source_target = source[:name]
                  source_code = source[:code]
                  target_result = source_target.is_a?(String) ? eval(source_target) : send(source_target)
                  #log :debug, "Data method '#{name}' with source_target '#{source_target}': #{target_result.class}"
                  
                  if target_result
                    result = case
                      when source_code.is_a?(Proc)
                        target_result.instance_eval(&source_code)
                      when source_code.is_a?(String)
                        target_result.send(:eval, source_code)
                      when source_code.is_a?(Array)
                        target_result.send(:eval, source_code.join('.'))
                      when source_code.nil?
                        target_result
                      else
                        nil
                    end
                  end # if
                  
                  #log :debug, "Data method '#{name}' end of source loop '#{source}': #{result.class}"
                  break if result
                end # sources.each
              
              end # case
              result ||= method_opts[:default_value]
              #log :debug, "Data method '#{name}' returning: #{result}"
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
      def self.new(*args)
        opts = Mashy.new(args.last.is_a?(Hash) ? args.pop : {})
        name = args[0].to_s
        klass = args[1]
        setup_block  = Proc.new if block_given?
        new_object = allocate
        %w(name scope scope_opts condition source storage default_value setup_block info_key).each do |property|
          new_object[property] = nil
        end
        new_object[:name] = name if name
        new_object[:klass] = klass
        new_object[:setup_block] = setup_block if setup_block
        new_object.merge!(opts)
        new_object.send(:initialize, opts, &setup_block)
        new_object
      end
      
      def initialize(opts = {})
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
      
      def source(*args)
        return self[__method__] unless args.any?
        opts = args.last.is_a?(Hash) ? args.pop : Mashy.new
        name = args.shift
        code = args if args.any?
        prc = block_given? ? Proc.new : nil
        
        self[:source] ||= Hashie::Array.new
        #OmniAuth.logger.log(0, "(slack) DataMethod 'source' with (#{name}, #{opts}, #{prc})")
        source_hash = Mashy.new({name: name, code: code}.merge(opts))
        source_hash[:code] = Proc.new if block_given?
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

      # Dependencies for this DataMethod instance.
      # For example try this: Strategy.data_methods.each{|k,v| puts "#{k}: #{v.api_dependencies_array(Strategy).inspect}" };nil
      def dependency_array
        source.inject([]) do |ary,src|
          src_name = src[:name].to_s
          #src_name[/^api_/] && ary << src_name
          ary << src_name
          sub_method = klass.data_methods[src_name]
          sub_method ? ary | sub_method.dependency_array : ary 
        end
      end
      
      # Dependency tree for this DataMethod instance.
      # For example try this: Strategy.data_methods.each{|k,v| puts "#{k}: #{v.api_dependencies_hash(Strategy).inspect}" };nil
      # or try this: y Strategy.data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.api_dependencies_hash(Strategy); h}
      def dependency_hash
        source.inject({}) do |hsh,src|
          ary = []
          src_name = src[:name].to_s
          #src_name[/^api_/] && ary << src_name
          sub_method = klass.data_methods[src_name]
          hsh[src_name] = sub_method ? ary | sub_method.dependency_array : ary
          hsh
        end   
      end
              
    end # DataMethod
  end # Slack
end # OmniAuth

