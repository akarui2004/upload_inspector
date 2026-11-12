# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.libs << 'test' << 'lib'
  t.test_files = FileList['test/**/*_test.rb']
end

task default: :test

desc 'Write the hostile sample corpus to DIR (default tmp/samples) to cross-check with real readers or scanners'
task :samples, [:dir] do |_, args|
  $LOAD_PATH.unshift(File.expand_path('lib', __dir__), File.expand_path('test', __dir__))
  require 'sample_virus_malware'

  dir = args[:dir] || 'tmp/samples'
  FileUtils.mkdir_p(dir)
  SampleVirusMalware::SAMPLES.each do |sample|
    status = sample.gap ? 'GAP' : sample.expect
    File.binwrite(File.join(dir, "#{sample.id}__#{sample.filename}"), sample.bytes)
    puts format('%-34s %-30s %s', sample.id, status, sample.attack)
  end
end
