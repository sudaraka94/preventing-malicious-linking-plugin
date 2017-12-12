# name: preventing-malicious-linking-plugin
# about: This is intended to be a plugin for preventing malicious liking in discourse forums.
# version: 0.1
# authors: Sudaraka Jayathilaka
# url: https://github.com/sudaraka94/preventing-malicious-linking-plugin.git

require 'uri'

# Returns an array of urls in the given string using regex
def getUrls(post_body)
  urls=Array[]
  words = post_body.split
  words.each do |word|
    if(/\S+\.\S+/.match(word))
      urls.push(word)
    end
  end
  return urls
end

# Returns malicious urls in a string
def getMalicioudUrls(urls)

end

DiscourseEvent.on(:post_created) do |post|
  urls=getUrls(post.raw)

  puts 'initialized'
  puts urls
end

