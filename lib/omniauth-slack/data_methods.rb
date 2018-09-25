require 'hashie'

module RefineArray
  refine Array do
    def sort_with(reference_array)
      # sort_by{|x| reference_array.index x.object_id}
      
      # This handles items not in the reference_array
      ai = reference_array.each_with_index.to_h
      sort_by { |e| [ai[e] || reference_array.size, e] }
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
          option :dependencies, nil  # <string,or,array,of,strings>
          option :dependency_filter, /.*/  # will be this /^api_/ when all data-methods & dependencies are properly declared.
          # Experimental, this won't load as early as we'd like.
          #option :data_method, nil   # <any valid args to Strategy.data_method, as an array>
        end
      end
            
      def dependencies(filter=nil)
        # If you provide a filter, this will return the master dependency list (filtered).
        if filter
          self.class.dependencies(filter).keys
        else
          options.dependencies || @dependencies ||= self.class.dependencies(dependency_filter).keys
        end
      end
      
      def dependency_filter
        options.dependency_filter
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
        # TODO: Try this instead now: data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.api_dependencies_hash; h}
        def dependency_tree
          #   result = Hashy.new
          #   data_methods.each do |key, val|
          #     #puts "DataMethods::Extensions.dependencies, data_methods.each, key '#{key}' val-type '#{val.class}'"
          #     result[key] = val.source.to_a.map{|s| s[:name].to_s}
          #   end
          #   result
          data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.dependency_hash; h}
        end

        # Flatten compiled dependency_tree into an array of uniq strings.
        def dependencies(filter = default_options.dependency_filter)
          dtree = dependency_tree
          deps  = dtree.values.inject([]){|ary,hsh| ary.concat hsh.keys}
          meths = dtree.keys.select(){|k| k.to_s[filter]}
          both = (deps.uniq | meths)
          #puts({deps: deps, meths: meths, both: both}.to_yaml)
          
          #both.inject({}){|h, v| h[v] = deps.count(v.to_s); h}
          both.inject({}){|h, v| h[v] = deps.count(v.to_s); h}.select{|k,v| k[filter]}
          
          #   dependency_tree.values.inject([]) do |ary, d1|
          #     d1.each {|k,v| ary << k; ary.concat(v.to_a)}
          #     ary
          #   end.uniq
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
                #return ivar_data
                result = ivar_data
            
              when (
                #log(:debug, "Data method '#{name}' asking has_scope? with '#{method_opts[:scope]}' and opts '#{method_opts[:scope_opts]}'")
                #(scopes = method_opts[:scope]) && !has_scope?(scopes, method_opts[:scope_opts]) ||
                # If scopes don't pass.
                (scopes = method_opts[:scope]) && scopes.any? && !has_scope?(scopes, method_opts[:scope_opts]) ||
                # If conditions don't pass.
                (conditions = method_opts[:condition]) && !(conditions.is_a?(Proc) ? conditions.call : eval(conditions)) #||
                # If this is an api-method and is not in the compiled dependency list.
                #name.to_s[/^api_/] && !dependencies.include?(name.to_s)
              )
                #log(:debug, "Data method '#{name}' returning from unmet scopes or conditions.")
                #result = method_opts[:default_value]
                result = nil  # see below
              else
                
                puts "Data method '#{name}' succeeded scopes & conditions."
                result = nil
                # TODO: Get rid of this dependencies block (see readme-dev).
                #       Redo this with the sources loop on top, and run thru master deps list only once.
                #       Logic:
                #         selected_sources = <source name is in user-deps || source name not in master-deps>
                #         selected_sources.sort_with(user-deps | master-deps)
                #         selected_sources.each {execute}
                dependencies(/.*/).each do |dep_name|
                  #log(:debug, "Data method '#{name}' with dep_name '#{dep_name}'")
                  #sources = method_opts[:source].select{|src| src[:name].to_s == dep_name.to_s }
                  #sources = method_opts[:source].select{|src| src[:name].to_s == dep_name.to_s || method_opts.api_dependencies_array.include?(dep_name) && !self.class.dependencies.include?(src[:name].to_s)}
                  sources = method_opts[:source].select do |src|
                    src.name.to_s == dep_name.to_s ||
                    !dependencies(/.*/).include?(src.name.to_s)
                  end
                  log(:debug, "Data method '#{name}' with dep_name '#{dep_name}' with selected sources: #{sources}") if sources.any?
                  sources.each do |source|
                    #puts "Processing source for '#{name}': #{source}"
                    source_target = source[:name]
                    source_code = source[:code]
                    target_result = source_target.is_a?(String) ? eval(source_target) : send(source_target)
                    #puts "Data method '#{name}' with source_target '#{source_target}': #{target_result.class}"
                    
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
                    
                    #puts "Data method '#{name}' end of source loop '#{source}': #{result.class}"
                    break if result
                  end # sources.each
                  
                  #puts "Data method '#{name}' end of dependencies loop '#{dep_name}': #{result.class}"
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
      
      #def source(name = nil, opts = Mashy.new)
      def source(*args)
        return self[__method__] unless args.any?
        opts = args.last.is_a?(Hash) ? args.pop : Mashy.new
        name = args.shift
        code = args if args.any?
         
        self[:source] ||= Hashie::Array.new
        prc = block_given? ? Proc.new : nil
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
      
      # # For example try this: Strategy.data_methods.each{|k,v| puts "#{k}: #{v.api_dependencies(Strategy).inspect}" };nil
      # def api_dependencies(strategy)
      #   source.inject([]) do |ary,src|
      #     # name = d[:name].to_s
      #     # name[/^api_/] && a << name
      #     # sub_method = strategy.data_methods[name]
      #     # sub_method ? a | sub_method.api_dependencies(strategy) : nil
      #     # a
      #     ary | source_api_dependencies(src, strategy)
      #   end
      # end
      
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

