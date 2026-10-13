// Services where a dangling CNAME can be claimed by an attacker, with HTTP body fingerprints.
// Based on public research (e.g. EdOverflow/can-i-take-over-xyz). "nxdomain: true" means a dangling target alone is enough.
export const SERVICES = [
  { name: 'AWS S3', re: /(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$|\.s3-website[.-]/, fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { name: 'AWS Elastic Beanstalk', re: /\.elasticbeanstalk\.com$/, fingerprints: [], nxdomain: true },
  { name: 'GitHub Pages', re: /\.github\.io$/, fingerprints: ["There isn't a GitHub Pages site here", 'For root URLs (like http://example.com/) you must provide an index.html file'] },
  { name: 'Heroku', re: /\.(herokuapp|herokudns|herokussl)\.com$/, fingerprints: ['No such app', 'herokucdn.com/error-pages/no-such-app.html', "There's nothing here, yet."] },
  { name: 'Microsoft Azure', re: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azure-api\.net|azurecontainer\.io|azurefd\.net|azureedge\.net|azurestaticapps\.net|azurehdinsight\.net|database\.windows\.net|redis\.cache\.windows\.net|search\.windows\.net|servicebus\.windows\.net|visualstudio\.com)$/, fingerprints: ['404 Web Site not found', 'Error 404 - Web app not found'], nxdomain: true },
  { name: 'Shopify', re: /\.myshopify\.com$/, fingerprints: ['Sorry, this shop is currently unavailable', 'Only one step left!'] },
  { name: 'Fastly', re: /\.fastly\.net$/, fingerprints: ['Fastly error: unknown domain'] },
  { name: 'Pantheon', re: /\.pantheonsite\.io$/, fingerprints: ['The gods are wise, but do not know of the site which you seek'] },
  { name: 'Tumblr', re: /^domains\.tumblr\.com$/, fingerprints: ["Whatever you were looking for doesn't currently exist at this address"] },
  { name: 'Ghost', re: /\.ghost\.io$/, fingerprints: ['Domain error', 'The thing you were looking for is no longer here'] },
  { name: 'Surge.sh', re: /(^|\.)surge\.sh$/, fingerprints: ['project not found'] },
  { name: 'Bitbucket', re: /\.bitbucket\.io$/, fingerprints: ['Repository not found'] },
  { name: 'Netlify', re: /\.netlify\.(app|com)$/, fingerprints: ['Not Found - Request ID'] },
  { name: 'Webflow', re: /(^|\.)proxy(-ssl)?\.webflow\.com$|\.webflow\.io$/, fingerprints: ["The page you are looking for doesn't exist or has been moved"] },
  { name: 'Zendesk', re: /\.zendesk\.com$/, fingerprints: ['Help Center Closed'] },
  { name: 'ReadMe', re: /\.readme\.io$/, fingerprints: ['Project doesnt exist... yet!'] },
  { name: 'Unbounce', re: /\.unbouncepages\.com$/, fingerprints: ['The requested URL was not found on this server'] },
  { name: 'Help Scout', re: /\.helpscoutdocs\.com$/, fingerprints: ['No settings were found for this company'] },
  { name: 'Strikingly', re: /\.strikinglydns\.com$/, fingerprints: ['PAGE NOT FOUND'] },
  { name: 'Fly.io', re: /\.fly\.dev$/, fingerprints: [], nxdomain: true },
  { name: 'Agile CRM', re: /\.agilecrm\.com$/, fingerprints: ['Sorry, this page is no longer available'] },
  { name: 'Canny', re: /\.canny\.io$/, fingerprints: ['Company Not Found', 'There is no such company'] },
  { name: 'Statuspage', re: /\.statuspage\.io$/, fingerprints: ['Better Status Communication', 'You are being <a href'] },
  { name: 'Wordpress.com', re: /\.wordpress\.com$/, fingerprints: ["Do you want to register"] },
  { name: 'Google Cloud Storage', re: /^c\.storage\.googleapis\.com$/, fingerprints: ['The specified bucket does not exist', 'NoSuchBucket'] },
];

export function matchService(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return SERVICES.find((s) => s.re.test(h)) || null;
}
