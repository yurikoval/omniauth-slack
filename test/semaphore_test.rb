require 'helper'

class TestClass
  attr_accessor :semaphores
  prepend OmniAuth::Slack::Semaphore

  def test_semaphore_1
    semaphore
  end
  
  def test_semaphore_2
    semaphore
  end
end

describe OmniAuth::Slack::Semaphore do
  describe 'semaphore' do
    it "gets a mutex specific to calling method" do
      tc_instance = TestClass.new
      assert_kind_of Mutex, tc_instance.test_semaphore_1
      assert_equal tc_instance.test_semaphore_2, tc_instance.semaphores['test_semaphore_2']
    end
  end
end


