import { withPluginApi } from 'discourse/lib/plugin-api';

export default {
    name: 'malicious-url-warnings',
    initialize(){
        withPluginApi('0.8.10', api => {
            api.includePostAttributes('flagged_threats');

            api.decorateWidget('post:before', helper => {
                const flagged_threats = helper.attrs.flagged_threats;
                if(flagged_threats != null){
                    let text='Following urls in the post are malicious !';
                    for (let i = 0; i < flagged_threats.length; i++) {
                        text += ' <br> > '+flagged_threats[i].url ;
                    }
                    text='<p>'+text+'</p>';
                    let html= new Handlebars.SafeString(text);
                    return helper.rawHtml(`${html}`);
                }

            });
        });
    }
};