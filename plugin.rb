# name: preventing-malicious-linking-plugin
# about: This is intended to be a plugin for preventing malicious liking in discourse forums.
# version: 0.1.1
# authors: Sudaraka Jayathilaka
# url: https://github.com/sudaraka94/preventing-malicious-linking-plugin.git


enabled_site_setting :prevent_malicious_linking_enabled

require 'uri'
require 'faraday'
require 'json'

register_asset 'stylesheets/common/malicious-linking.scss'

after_initialize do

  api_key = SiteSetting.prevent_malicious_linking_google_safebrowsing_api_key
  client_id = SiteSetting.prevent_malicious_linking_google_safebrowsing_client_id
  client_version = SiteSetting.prevent_malicious_linking_google_safebrowsing_client_version

  Post.register_custom_field_type('flagged_threats', :json)
  topic_view_post_custom_fields_allowlister { ['flagged_threats'] }

  # Returns an array of urls in the given string using regex
  def getUrls(post_body)
    urls=Array[]
    words = post_body.split
    words.each do |word|
      if word!=''
        if(/(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)/.match(word))
          urls.push(word)
        end
      end
    end
    return urls.uniq
  end

  # Returns malicious urls in a string
  def getMalicioudUrls(urls,api_key,client_id,client_version)
    if urls==[] || api_key==''
      if api_key==''
        puts "Prevent Malicious Linking Plugin : Failed to query urls due to missing parameters. Please enter a valid API key"
      end
      return []
    end
    url_str=''
    # Process urls and create request body
    urls.each do |url|
      if(url_str=='')
        url_str=url_str+"{\"url\": \"#{url}\"}"
      else
        url_str=url_str+",{\"url\": \"#{url}\"}"
      end
    end
    req_body="{\"client\": {\"clientId\":\"#{client_id}\",\"clientVersion\": \"#{client_version}\"},\"threatInfo\":{\"threatTypes\":[\"MALWARE\", \"SOCIAL_ENGINEERING\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\": [\"URL\"],\"threatEntries\": [#{url_str}]}}"
    response = Faraday.post do |req|
      req.url "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=#{api_key}"
      req.headers['Content-Type'] = 'application/json'
      req.body = req_body
    end

    parsed_response=JSON.parse response.body

    if parsed_response == {}
      return []
    elsif parsed_response['error'] != nil
      puts "Prevent Malicious Linking Plugin : Failed to query urls. Please enter valid patameters and retry"
      return []
    end

    threats=parsed_response['matches']

    flagged_threats=[]

    threats.each do |threat|
      url_record=Hash.new()
      url_record['threatType']=threat['threatType']
      url_record['url']=threat['threat']['url']
      flagged_threats.push(url_record)
    end

    return flagged_threats.to_json

  end

  def flag_threats(post,api_key,client_id,client_version)
    return unless SiteSetting.prevent_malicious_linking_enabled?
    urls=getUrls(post.raw)
    flagged_threats=getMalicioudUrls(urls,api_key,client_id,client_version)
    post.custom_fields['flagged_threats'] =flagged_threats
    post.save_custom_fields(true)
  end

  DiscourseEvent.on(:post_created) do |post|
    flag_threats(post,api_key,client_id,client_version)
  end

  DiscourseEvent.on(:post_edited) do |post|
    flag_threats(post,api_key,client_id,client_version)
  end

  add_to_serializer(:post, :flagged_threats) { post_custom_fields["flagged_threats"] }

end
