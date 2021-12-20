from PIL import Image

RESIZE = 0.6

PICS_TO_RESIZE = [
    'c8llision.png',
    'close_is_stop.png',
    'messin6.png',
    'messin6_win.png',
    'mi5sing.png',
    'mi5sing_baba_near_flag.png',
    'mi5sing_key_is_baba.png',
    'mi5sing_skull_key.png',
    'mov7ng.png',
    'mov7ng_change_dir.png',
    'mov7ng_index_7.png',
    'mov7ng_index_7_first_move.png',
    'ran9om.png',
    'ran9om_secret_move.png',
    'flag.png',
]

for pic in PICS_TO_RESIZE:
    im = Image.open(pic)
    width, height = im.size
    
    width, height = int(width * RESIZE), int(height * RESIZE)
    
    im = im.resize((width, height), Image.ANTIALIAS)
    im.save(pic)
