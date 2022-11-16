# coding: utf-8

Gem::Specification.new do |spec|
  spec.name          = "jekyll-swiss"
  spec.version       = "0.4.0"
  spec.authors       = ["broccolini"]
  spec.email         = ["diana.mounter@gmail.com"]

  spec.summary       = %q{A bold typographic theme for Jekyll, inspired by Swiss design.}
  spec.homepage      = "http://broccolini.net/swiss"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").select do |f|
    f.match(%r{^(assets|_(includes|layouts|sass)/|(LICENSE|README)((\.(txt|md|markdown)|$)))}i)
  end

  spec.add_development_dependency "jekyll", "~> 4.3.1"
  spec.add_development_dependency "bundler", "~> 2.3.25"
  spec.add_development_dependency "rake", "~> 13.0.6"
end
