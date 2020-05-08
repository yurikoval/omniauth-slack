require 'hashie'
require 'omniauth'
require 'omniauth-slack/refinements'
require 'omniauth-slack/semaphore'
require 'omniauth-slack/debug'

module OmniAuth
  module Slack
    using ArrayRefinements
    using StringRefinements
    
    # TODO: Add +Returns+ to comment blocks for methods.
  
    # Enhanced hash class based on Hashie.
    # Includes the following feature additions
    #
    # * Merge initializer for creating new instances
    # * Accessor methods (read & write) for each attribute
    # * Query methods for each attribute
    # * Indifferent access (method, symbol, string)
    #
    class Hashy < Hashie::Hash
      include Hashie::Extensions::MergeInitializer
      #include Hashie::Extensions::MethodReader
      include Hashie::Extensions::MethodAccess
      include Hashie::Extensions::MethodQuery
      # Note that this extension will introduce procs into the hash, which won't serialize.
      include Hashie::Extensions::IndifferentAccess
      
      def self.inherited(other)
        other.send :include, OmniAuth::Slack::Debug
      end
    end

    # Declarative method dependency management.
    #
    # Goals
    #
    # * Get the most data from the fewest API calls.
    # * Consider scopes required for each API call.
    # * Define additional conditions to be met for each API call.
    # * Assign data source priority for methods that can pull from multiple sources.
    # * Skip descendant source traversal, when the end point is known to be blocked/down.
    #
    # Include +DataMethods+ module in your +OmniAuth::Strategy+ class and/or in your
    # +OAuth2::AccessToken+ class to gain flexible method dependency management.
    # Control which data-methods get called and in what priority
    # with the +OmniAuth::Builder+ block provider option +:dependencies+.
    #
    #   provider :slack, KEY, SECRET, dependencies: (['my_api_method', 'another_api_method'])
    #
    module DataMethods
      include OmniAuth::Slack::Debug
      
      # Perform operations on the class that included DataMethods.
      def self.included(other)
        debug{"#{other} included #{self}"}
        other.instance_eval do
          prepend Semaphore
          extend Extensions
          include OmniAuth::Slack::Debug
          singleton_class.send :attr_reader, :data_methods, :logger
          @logger = OmniAuth.logger
          @data_methods ||= Hashy.new
        end
      end

      
      # Strategy or AccessToken instance data-method dependencies.
      # :markup: tomdoc
      #
      # The methods listed here will be called, in listed order,
      # when resolving the source of any given data-method.
      # 
      # Data-methods not listed here will not be called,
      # UNLESS they are also omitted from the master dependency
      # list using the dependency_filter regexp.
      #
      # If given a regexp, returns a filtered master dependency list.
      #
      # Otherwise returns the user-defined dependency list, or the class-level
      # dependency list with the user (or default) filter applied.
      #
      # filter  - Regexp matching the names of data-methods to control (default: nil)
      #
      def dependencies(filter=nil)
        raw = if !filter.nil?
          self.class.dependencies(filter).keys
        else
          (options.dependencies if options.respond_to?(:dependencies)) || @dependencies ||= self.class.dependencies(dependency_filter).keys
        end
        
        case raw
        when String; eval(raw)
        when Proc; instance_eval(&raw)
        else raw
        end
      end
      
      # Filters the master data-method dependency list.
      # Data-methods matched by the dependency_filter will be
      # controlled by the gating logic of scope, conditions,
      # and order-listed in :dependencies.
      #
      # This is intended to be set per provider-strategy (per gem),
      # and should generally never be used by the user/developer
      # consuming the gem.
      #
      # A sane default is generally something that matches all API method calls.
      # 
      #   provider :oauth2_provider, KEY, SECRET, dependency_filter:/^api_/
      #
      def dependency_filter
        (options.dependency_filter if options.respond_to?(:dependency_filter)) || @dependency_filter
      end
      
      # Points to +self.class.data_methods+.
      def data_methods; self.class.data_methods; end
      
      # Adds result of each method to +info+ hash, keyed by +:info_key+.
      # TODO: Rework this method to run only for methods with a defined +:info_key+.
      # TODO: Is this still used? It is disabled in the Strategy class.
      def apply_data_methods(rslt = Hashy.new)
        data_methods.each do |name, opts|
          key = opts[:info_key]
          #log(:debug, "Applying key '#{key}' with method '#{name}'")
          debug{"Applying key '#{key}' with method '#{name}'"}
          next unless key
          rslt[key] ||= send(name)
          #log(:debug, "Applying key '#{key}' with method '#{name}': #{rslt[key]}")
          rslt
        end
      end
      
      # Preloads api calls with a pool of threads.
      def preload_data_with_threads(num_threads=1, method_names=dependencies)
        return unless num_threads > 0 && !@preloaded_data
        @preloaded_data = 1
        #preload_methods = method_names || dependencies + options.additional_data.to_h.keys
        preload_methods = case method_names
          #when String; method_names.split(SIMPLE_WORD_SPLIT_REGEXP)
          when String; method_names.words
          when Array; method_names
          else []
        end
        log :info, "Preloading (#{preload_methods.size}) methods with (#{num_threads}) threads"  #: #{preload_methods}"
        work_q = Queue.new
        preload_methods.each{|x| work_q.push x }
        workers = num_threads.to_i.times.map do
          Thread.new do
            begin
              while x = work_q.pop(true)
                log :debug, "Preloading #{x} in thread #{Thread.current.object_id}."
                send x
              end
            rescue ThreadError
            end
          end
        end
        workers.map(&:join); "ok"
      end
      

      # Methods to be extended onto the class that included DataMethods.
      # See #self.included above.
      module Extensions

        # Lists all defined DataMethod instances and their dependencies.
        def dependency_tree
          return {} unless data_methods.to_h.any?
          data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.dependency_hash; h}
        end

        # Strategy or AccessToken class dependencies.
        # Flattens compiled dependency_tree into an array of uniq strings.
        #
        # TODO: I think this can be cleaned up & simplified.
        #
        def dependencies(filter = nil)
          filter ||= /.*/
          dtree = dependency_tree
          deps  = dtree.values.inject([]){|ary,hsh| ary.concat hsh.keys}
          # TODO: Do we still need this meths list?
          meths = dtree.keys.select(){|k| k.to_s[filter]}
          both = (deps.uniq | meths).sort_with(dtree.keys)
          both.delete('default')
          both.inject({}){|h, v| h[v] = deps.count(v.to_s); h}.select{|k,v| k[filter]}
        end  
        
        # Lists dependencies that are missing callable methods.
        def missing_dependencies
          dependencies.keys.select{|m| !method_defined?(m) && !private_method_defined?(m)}
        end
        
        # Defines a DataMethod object.
        #
        # TODO: Should the bulk of this method be combined with DataMethod#new ?
        #
        def data_method(*args) # (name, optional-default-val, optional-opts, &optional-block)
          #logger.debug "(slack) Building data_method object (#{name}, #{opts})"
          
          opts = args.last.is_a?(Hash) ? args.pop : Hashy.new
          name = args.shift
          default_val  = args.shift
          blk = Proc.new if block_given?
          debug{"Defining data_method object (#{name}, #{opts})"}
          
          data_methods[name] = DataMethod.new(name, self, default_val, opts, &blk)
                    
          define_method(name) do
            semaphore(name).synchronize { data_methods[__method__].call(self) }
          end
                    
          data_methods[name]
        end
        
      end # Extensions
    end # DataMethods


    # A DataMethod instance holds the logic, scope, conditions, and sources
    # of a defined data-method.
    #
    # When a data method is defined with the class method +data_method+,
    # and passed a block, the block is evaluated in the context of the
    # associated DataMethod instance.
    #
    # The instance methods of DataMethod are used to facilitate
    # setting the attributes of the data-method.
    #
    # Example data-method definition in the Strategy class:
    # 
    #   data_method :my_api_method do
    #     scope classic:'identity.basic', identity:'identity:read:user'
    #     scope team:'conversations:read', app_home:'chat:write'
    #     # override the default logic (or) within each scope query.
    #     scope_logic 'or'
    #     # override the name of the cache variable. default is method-name. false disables cache for this method.
    #     storage true
    #     condition proc{ true }
    #     condition proc{ ! false }
    #     default_value Hash.new
    #     source :access_token do
    #       get('/api/users.identity', headers: {'X-Slack-User' => user_id}).parsed
    #     end
    #   end
    #   
    #   data_method :user_name do
    #     source :my_api_method do
    #       user.name
    #     end
    #   end
    #
    class DataMethod < Hashy

      # Creates a new instance of DataMethod
      # :markup: tomdoc
      #
      # This should be called by +DataMethods.data_method+ macro,
      # and is generally not intended for userspace.
      # 
      # name               - Name of data-method as String or Symbol.
      # klass              - Class that data-method is defined under.
      # default_proc       - A Proc that evaluates to the default value, default: nil.
      # options_hash       - Hash of options, default: nil.
      # block              - Block containing class methods describing data-method options, default: nil.
      #
      # TODO: What data types do these args accept?
      #
      def self.new(*args)  #(name, klass, optional-default-proc, optional-opts, &optional-block)
        debug{"DataMethod.new with args: #{args}"}
        opts = Hashy.new(args.last.is_a?(Hash) ? args.pop : {})
        new_object = allocate
        %w(name scope condition source storage default_value setup_block info_key klass).each do |property|
          new_object[property] = nil
        end
        
        new_object.merge!(opts)
        new_object.name = args.shift
        new_object.klass = args.shift
        new_object.default_value ||= args.shift #if args[0].is_a?(Proc)
        new_object.setup_block ||= Proc.new if block_given?

        new_object.send(:initialize, opts, &new_object.setup_block)
        new_object
      end
      
      def initialize(opts = {})
        debug('data_method'){"initializing #{self.name}."}
        instance_eval(&Proc.new) if block_given?
      end
      
      # Overrides instance debug to insert local :klass as Class,
      # instead of default, which would be DataMethod.
      def debug(method_name=nil, _klass=klass, &block)
        #puts caller_method_name
        method_name ||= caller_method_name
        super(method_name, _klass, &block)
      end
      
      def log(type, text)
        klass.logger.send(type, "(#{klass.name.split('::').last.downcase} data_method) #{text}") if klass.respond_to?(:logger)
      end
      
      # Gets/sets scope queries.
      # Expects same args as OmniAuth::Slack::OAuth2::AccessToken#has_scope?
      def scope(*args)
        #return self[__method__] unless (args.any?)
        raw_scope = self[__method__]
        unless (args.any?)
          return case raw_scope
            when Array; raw_scope
            when Hash; Hashie::Extensions::SymbolizeKeys.symbolize_keys(raw_scope)
            else raw_scope
          end
        end
        debug{"Declaring #{name}.scope: #{args}"}
        self[:scope] = args #.flatten.compact
      end
      
      # Gets/sets a source for this DataMethod.
      # :markup: tomdoc
      #
      # name   - Method or variable name to resolve.
      # proc   - Proc to execute in context of :name.
      # opts   - Hash or source options.
      # block  - Block of code to execute in context of :name.
      #
      def source(*args) # (optional-name, optional-proc, optional-opts, &optional-block)
        #return self[__method__] unless args.any?
        return source_array unless args.any?
        opts = args.last.is_a?(Hash) ? args.pop : Hashy.new
        source_name = args.shift if [String, Symbol].any?{|t| args[0].is_a?(t)}
        code = case
          when block_given?; Proc.new
          when opts[:code]; opts.delete(:code)
          when args[0].is_a?(Proc); args.shift
          when args.any?; args
          else nil
        end          
        self[:source] ||= Hashie::Array.new
        #log :debug, "Declaring #{source_name}.source: #{name}, #{opts}, #{prc}"
        debug{"Declaring source :#{source_name} for #{name}: #{opts}, #{code}"}
        source_hash = Hashy.new({name: source_name, code: code}.merge(opts))
        self[:source] << source_hash
      end
      
      # Gets array of defined sources.
      def source_array
        Hashie::Array.new.concat( [self[:source]].flatten(1).compact.map do |v|
          case v
          when Hash; Hashy.new(v)
          when String; Hashy.new(name: 'default', code: proc{eval(v)})
          when Proc; Hashy.new(name: 'default', code: v)
          else Hashy.new(name: 'unknown', code: v)
          end
        end)
      end
      private :source_array
      
      # Gets/sets cache storage name (or disable with false).
      #
      # TODO: Change name of this method to :cache_name or :cache_as.
      #
      def storage(arg = nil)
        return self[__method__] unless arg
        #log :debug, "Declaring #{name}.cache_storage: #{arg}"
        debug{"Declaring #{name}.cache_storage: #{arg}"}
        self[:storage] = arg
      end
      
      # Gets/sets additional conditions for gating this method.
      def condition(code = nil)
        code = block_given? ? Proc.new : code
        return self[__method__] unless code
        self[:condition] ||= []
        #log :debug, "Declaring #{name}.condition: #{code}"
        debug{"Declaring #{name}.condition: #{code}"}
        self[:condition] << code
      end
      
      # Gets/sets defaut_value.
      #
      # TODO: Possibly remove the :default_value variable, while
      # making this method define a :default source.
      #
      def default_value(arg = nil)
        return self[__method__] unless arg
        #log :debug, "Declaring #{name}.default_value: #{arg}"
        debug{"Declaring #{name}.default_value: #{arg}"}
        self[:default_value] = arg
      end

      # Compiles dependencies for this DataMethod instance.
      # 
      # Example:
      #
      #   Strategy.data_methods.each{|k,v| puts "#{k}: #{v.api_dependencies_array(Strategy).inspect}" };nil
      #
      def dependency_array
        return [] unless sources = source
        sources.inject([]) do |ary,src|
          src_name = src.is_a?(Hash) && src[:name].to_s #|| 'default'
          ary << src_name if src_name
          sub_method = klass.data_methods[src_name]
          sub_method ? ary | sub_method.dependency_array : ary 
        end
      end
      
      # Compiles dependency tree for this DataMethod instance.
      #
      # Examples:
      #
      #   Strategy.data_methods.each{|k,v| puts "#{k}: #{v.api_dependencies_hash(Strategy).inspect}" };nil
      #
      #   y Strategy.data_methods.inject({}){|h,a| k,v = a[0], a[1]; h[k] = v.api_dependencies_hash(Strategy); h}
      #
      def dependency_hash
        return {} unless sources = source
        sources.inject({}) do |hsh,src|
          ary = []
          src_name = src.is_a?(Hash) && src[:name].to_s #|| 'default'
          sub_method = klass.data_methods[src_name] if src_name
          hsh[src_name] = sub_method ? ary | sub_method.dependency_array : ary
          hsh
        end   
      end
      
      # Resolves all conditions and returns true or false.
      def resolve_conditions(strategy_or_access_token, conditions = condition)
        #log :debug, "Resolve_conditions for data-method '#{name}' with conditions '#{conditions}'"
        debug{"for data-method '#{name}' with conditions '#{conditions}'"}
        return true unless conditions
        rslt = case conditions
          when Proc; strategy_or_access_token.instance_eval(&conditions)
          when String; strategy_or_access_token.send :eval, conditions.to_s
          when Array;
            if conditions.size > 1
              conditions.all?{|c| resolve_conditions(strategy_or_access_token, c)}
            else
              #strategy.send :eval, conditions[0]
              resolve_conditions(strategy_or_access_token, conditions[0])
            end
          else conditions
        end ? true : false
        #log :debug, "Resolve_conditions for '#{name}' with '#{conditions}' result '#{rslt}'"
        debug{"for data-method '#{name}' with '#{conditions}' result '#{rslt}'"}
        rslt
      end
      
      # Resolves all scope queries and returns true or false.
      def resolve_scope(strategy_or_access_token)
        scopes = scope
        case scopes
          when NilClass; true
          when :empty?.to_proc; true
          when Array;
            debug{"array #{scopes}"}
            strategy_or_access_token.send(:has_scope?, *scopes)
          when Hash;
            debug{"hash #{scopes}"}
            strategy_or_access_token.send(:has_scope?, **scopes)
          else raise "Scope query object #{scopes} was not handled."
        end
      end
      
      # Resolves a single source definition.
      def resolve_source(src, strategy_or_access_token)
        source_target = src.respond_to?(:name) ? src.name : strategy_or_access_token
        source_code = case
          when src.respond_to?(:code);src.code
          when src.is_a?(Proc); src
          else proc{self}
        end
        #log :debug, "'#{name}' calling source_target '#{source_target}' on klass_instance '#{strategy_or_access_token}' with code '#{source_code}'."
        #debug{"'#{name}' calling source_target '#{source_target}' on klass_instance '#{strategy_or_access_token}' with code '#{source_code}'."}
        
        target_result = case source_target
          when 'default'
            strategy_or_access_token
          when NilClass
            strategy_or_access_token
          when String
            strategy_or_access_token.send(:eval, source_target)
          when Symbol
            strategy_or_access_token.send(source_target)
          when Proc
            strategy_or_access_token.instance_eval(&source_target)
          else
            source_target
        end
        #log :debug, "Data method '#{name}' with source_target '#{source_target}': #{target_result.class}"
        #debug{"Data method '#{name}' with source_target '#{source_target}': #{target_result.class}"}
        
        if target_result
          case source_code
            when Proc
              target_result.instance_eval(&source_code)
            when String
              target_result.send(:eval, source_code)
            when Array
              target_result.send(:eval, source_code.join('.'))
            when NilClass
              target_result
            else
              nil
          end
        end
      end
      
      # Resolves the default-value, if defined, or returns nil.
      def resolve_default_value(strategy_or_access_token)
        dval = default_value
        case dval
        # Since dval could be string or symbol, the only time it should be processed is when it is a proc.
        #
        # when String
        #   strategy_or_access_token.send(:eval, dval)
        # when Symbol
        #   strategy_or_access_token.send(dval)
        when Proc
          strategy_or_access_token.instance_eval(&dval)
        else
          dval
        end
      end
      
      # Selects valid accessible sources to attempt resolution on.
      def select_sources(strategy_or_access_token)
        sources = source
        strategy_or_access_token.instance_eval do
          strategy_or_access_token_dependencies = dependencies
          master_dependencies_filtered = dependencies(dependency_filter)
          sources.select do |src|
            strategy_or_access_token_dependencies.include?(src.name.to_s) ||
            !master_dependencies_filtered.include?(src.name.to_s) ||
            src.name == 'default'
          end.sort_with(strategy_or_access_token_dependencies){|v| v.name.to_s}
        end
      end
      
      # Wraps a memoization-with-ivar around a given block.
      def with_cache(strategy_or_access_token, &block)
        storage_name = case storage
          when false; false
          when nil; name
          when storage; storage
        end
        if storage_name
          ivar_data = strategy_or_access_token.instance_variable_get("@#{storage_name}")
          return ivar_data if ivar_data
        end
        result = yield
        strategy_or_access_token.instance_variable_set("@#{storage_name}", result) if result && storage_name
        result
      end
      
      # Processes this DataMethod in the context of the given strategy-or-access-token instance.
      def call(strategy_or_access_token)
        with_cache(strategy_or_access_token) do
          result = nil
          resolve_scope(strategy_or_access_token) &&
          resolve_conditions(strategy_or_access_token) &&
          select_sources(strategy_or_access_token).each do |src|
            result = resolve_source(src, strategy_or_access_token)
            break if result
          end
          
          result ||= resolve_default_value strategy_or_access_token
          #log :debug, "Data method '#{name}' returning: #{result}"
          debug{"Data method '#{name}' returning: #{result}"}
          result
        end
      end
              
    end # DataMethod
  end # Slack
end # OmniAuth

