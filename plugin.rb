# name: preventing-malicious-linking-plugin
# about: This is intended to be a plugin for preventing malicious liking in discourse forums.
# version: 0.1
# authors: Sudaraka Jayathilaka
# url: https://github.com/sudaraka94/preventing-malicious-linking-plugin.git

require 'uri'
require 'faraday'
require 'json'

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

  url_str=''
  # Process urls
  urls.each do |url|
    if(url_str=='')
      url_str=url_str+"{\"url\": \"#{url}\"}"
    else
      url_str=url_str+",{\"url\": \"#{url}\"}"
    end
  end
  req_body="{\"client\": {\"clientId\":\"yourcompanyname\",\"clientVersion\": \"0.1\"},\"threatInfo\":{\"threatTypes\":[\"MALWARE\", \"SOCIAL_ENGINEERING\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\": [\"URL\"],\"threatEntries\": [#{url_str}]}}"
  puts req_body
  response = Faraday.post do |req|
    req.url "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=<api key>"
    req.headers['Content-Type'] = 'application/json'
    req.body = req_body
  end

  parsed_response=JSON.parse response.body
  threats=parsed_response['matches']
  if(threats.count()==1)
    puts "One threat found !"
  else
    puts threats.count().to_s+" threats found !"
  end
end

DiscourseEvent.on(:post_created) do |post|
  urls=getUrls(post.raw)
  puts 'initialized'
  getMalicioudUrls(urls)
  puts urls
end

