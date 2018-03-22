require 'rubygems'
require 'rake'
require 'rdoc'
require 'date'
require 'yaml'
require 'tmpdir'

desc "Generate blog files"
task :generate do
  system "bundle exec jekyll build"
end


desc "Generate and publish blog to gh-pages"
task :publish => [:generate] do
	Dir.mktmpdir do |tmp|
		system "mv _site/* #{tmp}"
		system "git checkout -B gh-pages"
    system "mv .git /tmp/.git"
		system "rm -rf *"
		system "mv #{tmp}/* ."
    system "mv /tmp/.git ."
		message = "Site updated at #{Time.now.utc}"
    system "echo www.badhombres.pro > CNAME"
		system "git add ."
		system "git commit -am \"#{message}\""
		system "git push origin gh-pages --force"
		system "git checkout master"
		system "echo yolo"
	end
end

task :default => :publish
