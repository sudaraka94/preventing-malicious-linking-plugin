import { withPluginApi } from 'discourse/lib/plugin-api';

export default {
    name: 'malicious-url-warnings',
    initialize(){
        withPluginApi('0.8.10', api => {
            api.includePostAttributes('flagged_threats');

            api.decorateWidget('post:after', helper => {
                const flagged_threats = helper.flagged_threats;
                return flagged_threats.toString();

            });
        });
    }
};