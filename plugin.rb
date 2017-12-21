# name: preventing-malicious-linking-plugin
# about: This is intended to be a plugin for preventing malicious liking in discourse forums.
# version: 0.1
# authors: Sudaraka Jayathilaka
# url: https://github.com/sudaraka94/preventing-malicious-linking-plugin.git

require 'uri'
require 'faraday'
require 'json'

# register_asset 'stylesheets/common/malicious-linking.scss'

after_initialize do

  Post.register_custom_field_type('flagged_threats', :json)

  TopicView.add_post_custom_fields_whitelister do |user|
    ["flagged_threats"]
  end

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

    response = Faraday.post do |req|
      req.url "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCAyFRbRwSl-XSlsmxrsw5jMeJQ3JikaVA"
      req.headers['Content-Type'] = 'application/json'
      req.body = req_body
    end

    parsed_response=JSON.parse response.body
    threats=parsed_response['matches']

    begin
      data=::PLuginStore.get('preventing-malicious-linking-plugin','data')
      flagged_threats=data['flagged_threats']
    rescue
      flagged_threats=Array[]
    end

    threats.each do |threat|
      url_record=Hash.new()
      url_record['threatType']=threat['threatType']
      url_record['url']=threat['threat']['url']
      flagged_threats.push(url_record)
    end

    return flagged_threats.to_json

  end

  DiscourseEvent.on(:post_created) do |post, opts|
    urls=getUrls(post.raw)
    puts 'initialized'
    flagged_threats=getMalicioudUrls(urls)
    post.custom_fields['flagged_threats'] =flagged_threats
    post.save_custom_fields(true)
    puts post.custom_fields['flagged_threats']
  end

  add_to_serializer(:post, :flagged_threats) { object.custom_fields["flagged_threats"] }
end

