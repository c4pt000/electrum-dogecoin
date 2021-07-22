#!/usr/bin/python
from StringIO import StringIO
import urllib2, os, zipfile, pycurl

crowdin_identifier = 'electrum'
crowdin_file_name = 'electrum-client/messages.pot'
locale_file_name = 'locale/messages.pot'

if os.path.exists('contrib/crowdin_api_key.txt'):
    crowdin_api_key = open('contrib/crowdin_api_key.txt').read()

    # Generate fresh translation template
    if not os.path.exists('locale'):
      os.mkdir('locale')

    cmd = 'xgettext -s --no-wrap -f app.fil --output=locale/messages.pot'
    print 'Generate template'
    os.system(cmd)

    # Push to Crowdin
    print 'Push to Crowdin'
    url = ('http://api.crowdin.net/api/project/' + crowdin_identifier + '/update-file?key=' + crowdin_api_key)

    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.POST, 1)
    fields = [('files[' + crowdin_file_name + ']', (pycurl.FORM_FILE, locale_file_name))]
    c.setopt(c.HTTPPOST, fields)
    c.perform()

    # Build translations
    print 'Build translations'
    response = urllib2.urlopen('http://api.crowdin.net/api/project/' + crowdin_identifier + '/export?key=' + crowdin_api_key).read()
    print response

# Download & unzip
print 'Download translations'
zfobj = zipfile.ZipFile(StringIO(urllib2.urlopen('http://crowdin.net/download/project/' + crowdin_identifier + '.zip').read()))

print 'Unzip translations'
for name in zfobj.namelist():
    if not name.startswith('electrum-client/locale'):
        continue
    if name.endswith('/'):
        if not os.path.exists(name[16:]):
            os.mkdir(name[16:])
    else:
        output = open(name[16:],'w')
        output.write(zfobj.read(name))
        output.close()

# Convert .po to .mo
print 'Installing'
for lang in os.listdir('./locale'):
    if lang.startswith('messages'):
        continue
    # Check LC_MESSAGES folder
    mo_dir = 'locale/%s/LC_MESSAGES' % lang
    if not os.path.exists(mo_dir):
        os.mkdir(mo_dir)
    cmd = 'msgfmt --output-file="%s/electrum.mo" "locale/%s/electrum.po"' % (mo_dir,lang)
    print 'Installing',lang
    os.system(cmd)
