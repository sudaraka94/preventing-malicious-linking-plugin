import { withPluginApi } from 'discourse/lib/plugin-api';

export default {
    name: 'malicious-url-warnings',
    initialize(){

        withPluginApi('0.8.10', api => {
            api.includePostAttributes('flagged_threats');

            api.decorateWidget('post:before', helper => {
                const flagged_threats = helper.attrs.flagged_threats;

                if(flagged_threats != [] && flagged_threats){
                    var warning=I18n.t('prevent_malicious_linking_warning');
                    let text=warning+'<br>';
                    let list='';
                    for (let i = 0; i < flagged_threats.length; i++) {
                        list += '<li>'+flagged_threats[i].url+'</li>' ;
                    }
                    list='<ul>'+list+'</ul>';
                    text='<div class="malicious-linking-warning">'+text+list+'</div>';
                    let html= new Handlebars.SafeString(text);
                    return helper.rawHtml(`${html}`);
                }
            });
        });
    }
};
