# HXP 2021 CTF - baba is you

This challenge was super super fun, a little harder than I expected and it's gonna take a lot of writing to cover...  
So strap on your helmets - here we go!  

## Description
```
I’m a huge fan of BABA IS YOU, so I created a Gameboy version of it. If you like it, consider playing the real deal.

If you want to be on the scoreboard, you may need your team’s token: https://2021.ctf.link/internal/profile Note: The token gets updated if you change your team’s password.

Solve all levels on the server for the flag.

Read the readme.md!
```

## Background

For those who are not familiar with [Baba is You](https://hempuli.com/baba/) - it's basically a puzzle solving game (one of my favourites) where you get to decide what the rules are.  
The game interface is fairly simple - you have a 2D screen with some tiles on it. There are 4 categories of tiles:
* Objects
* "is"
* Attributes
* Characters

Each `Object` tile represents a `Character`. So, for example, the object tile with the flag on it represents the Flag Character.  
An attribute is a certain funtion that can be given to a character. For example - the attribute `Win` is a tile marked with `W` and when given to a character it makes it the winning tile of the level.  
The attributes can be given to characters by putting the tiles `Object`, `is` , `Attribute` in order horizontally or vertically right next to each other:

![Flag is Win!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/fisw.png?raw=true)  

The 3 tiles in a row create a rule that says that the Flag Character on the bottom right is a tile that if you touch it - you win the level.  
The way to play the game is that you always have one character you control with the arrow keys and you can move around and push tiles to form rules.  
It's very hard to explain all the beauty and complexity in this game since almost EVERYTHING is customizable by creating these rules and there is a LOT I didn't cover, like `Object is Object` also works and replaces the second object with the first. I really suggest playing the game from the beginning and working through the levels to understand the whole concept as it is really hard to put in words and will take most of this write-up 😅  

## The Challange

The challenge consists of an implementation of `baba is you` for a Gameboy! I'm afraid to ask how many hours it took hxp to create that gem...  
We are supposed to play the game locally, solve all the levels and record our movements, then we can replay the movements to the server and the server will spit out the flag.  
Thankfully, hxp provided all of the tools needed to do all that - just run `./tas-emulator record moves.bin` and play!  

## Play-only levels

The first 6 levels are just a tutorial - I won't cover them. The next 4 levels are easy-ish. The first level that challenged me was `mi5sing` - although it doesn't require anything other than just thinking a little extra and took me WAAAAY too much time to solve, it's a good prequel for the first "actual" level. The setup:

![mi5sing!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mi5sing.png?raw=true)

Let's go over all existing rules in the map (left to write, top to bottom)
* `baba is you` - the weird elephant thingy is the character controlled by the player
* `flag is win` - touch the flag and win
* `key is open` - the key, if pushed onto the door, will open it (because the door is close)
* `skull is death` - don't touch the skull or die
* `door is close` - can't move or go through the door without the key (key is open)
* `wall is stop` - can't move or go through the wall

That's it.  
It's easy to see that we can't to anything with the key, skull or flag, since we can't get to them. We can't change the rules of the door or the wall, so that only leaves one interesting tile - the `baba` object.  
I didn't get into it too much in the background, but there is one more option for a valid rule in the game - `Object is Object`. If we put `skull is key` then the skull will turn into a key:

![mi5sing: skull is key!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mi5sing_skull_key.png?raw=true)

That doesn't help us at all of course... But we can turn the key into `baba`:

![mi5sing: key is baba!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mi5sing_key_is_baba.png?raw=true)

What does this weird `key is baba is you` rule do and what does it give us?  
The way that the game interprets the rule is just by evaluating both: `key is baba` and `baba is you` separately. We turned the key into `baba`. If you didn't play the game then I should explain what `baba is you` means - the `you` attribute gives you control over the character, so when you use the arrows keys, the game actually moves the entities that are assigned the attribute `you`.  
So now we have 2 characters of the type `baba` and both of them follow the rule `baba is you` so when we use the arrow keys - we control both of them. Move twice to the right:

![mi5sing: solved!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mi5sing_baba_near_flag.png?raw=true)

and up.

## The fun begins

Up until now we didn't require any extra knowledge other than just mastering the game. This new level, however, is unsolvable (afaik) using "traditional" knowledge of the game:

![messin6!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/messin6.png?raw=true)

Looks almost similar to the previous level, but not quite. We can no longer prepend anyting to the `baba is you` rule, so we can't use the trick we used in the prevous level. I think it's time to go deeper into the rabbit hole.  

From all the files in the archive there is only one that is actually important - `main.gb` - which is the "cartridge" of the game.  
The first thing I did was to just look at the binary and try to identify interesting sections, such as this one:

```
000019D0: FF 22 FF FF FF 6D 69 35  73 69 6E 67 00 02 02 06  ."...mi5sing....
000019E0: 6D 69 73 73 69 6E 67 00  04 07 73 6F 6D 65 74 68  missing...someth
000019F0: 69 6E 67 3F 00 FF 01 00  10 FF FF FF FF FF FF FF  ing?............
00001A00: FF FF FF 22 04 00 11 FF  06 00 14 FF FF FF FF FF  ..."............
00001A10: FF FF FF FF FF FF FF FF  FF FF 07 00 13 FF FF FF  ................
00001A20: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001A30: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001A40: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001A50: FF FF FF FF FF FF FF FF  FF FF FF FF FF 22 22 22  ............."""
00001A60: 22 FF FF FF FF FF FF FF  FF FF FF FF FF FF FF 22  ".............."
00001A70: 27 FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  '...............
00001A80: FF 25 FF FF 24 FF FF FF  FF FF FF FF FF FF FF FF  .%..$...........
00001A90: FF FF FF 22 26 FF FF FF  FF FF FF FF FF FF FF FF  ..."&...........
00001AA0: FF FF FF FF FF 22 22 22  22 FF FF 21 FF FF FF FF  .....""""..!....
00001AB0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001AC0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001AD0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001AE0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001AF0: FF FF FF FF FF FF FF FF  FF FF FF FF FF 05 00 15  ................
00001B00: 02 00 12 6D 65 73 73 69  6E 36 00 02 02 0D 6E 6F  ...messin6....no
00001B10: 77 20 69 20 61 6D 20 6A  75 73 74 00 04 0E 6D 65  w i am just...me
00001B20: 73 73 69 6E 67 20 61 72  6F 75 6E 64 00 22 01 00  ssing around."..
00001B30: 10 FF FF FF FF FF FF FF  FF FF FF 22 04 00 11 FF  ..........."....
00001B40: 06 00 14 FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001B50: FF FF 07 00 13 FF FF FF  FF FF FF FF FF FF FF FF  ................
00001B60: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001B70: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001B80: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001B90: FF FF FF FF FF 22 22 22  22 FF FF FF FF FF FF FF  ....."""".......
00001BA0: FF FF FF FF FF FF FF 22  27 FF FF FF FF FF FF FF  ......."'.......
00001BB0: FF FF FF FF FF FF FF FF  FF 25 FF FF 24 FF FF 21  .........%..$..!
00001BC0: FF FF FF FF FF FF FF FF  FF FF FF 22 26 FF FF FF  ..........."&...
00001BD0: FF FF FF FF FF FF FF FF  FF FF FF FF FF 22 22 22  ............."""
00001BE0: 22 FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  "...............
00001BF0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001C00: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001C10: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00001C20: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
```

Nice, this looks like the map of the level. From a simple count, the map is 0x12*0x0f = 0x10e. Let's look at our level:

![messin6: map!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/messin6_map.png?raw=true)

Looks pretty straighforward - `0xFF` is an empty tile, `0x00` is the `is` tile, `0x22` is a wall, etc. There are no hidden features.  

Guess it's time for IDA 😁  

If you've never reversed a Gameboy binary, you are in for a world of ~~pain~~ fun! Let's begin.  
The first thing I did is open it with IDA. From some version it natively supports Gameboy (choose Gameboy CPU type), although it almost doesn't contain any extra needed configurations. You will need to go to load the code into address `0`, go to the entry point at offset `0x100` and start code analysis from there. The RAM is at `0xc000 - 0xe000` and there is some HW access at `0xF000 - 0x10000` but that wasn't too important for me.  
However the assembly code looks horrible (for me anyway) and it's very hard to make sense of it... So I tried to open it in Ghidra. You will need [this Gameboy plugin](https://github.com/Gekkio/GhidraBoy).  
Ghidra seems to do a much better job than IDA in terms of parsing the file, memory segments and the generic decompiler makes it so much easier to look at. Before you notice stuff like this of course:

![ghidra fail!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/ghidra_fail_1.png?raw=true)

which basically means
```
    ...
    
    i++;
}while(i < 0x10e);
```
Since most operations on this CPU are 8bit - 16bit values need to be separated to separate 8bit values and evaluated separately... Hence the unreadable code.  
After a while, though, you get used to this and rely on your intuition: if there is a 0x1 and a 0xe there, it's probably 0x10e because that's the size of the map. Until, of course, you realize you guessed something completely wrong and the `convert_map_into_indices` function is actually just `memcpy` 😅😅  

After considerable reversing and understanding the internal workings, I noticed this (address `0x243a`, i called the function `apply_rules`):  

!["is" rules!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/is_rules.png?raw=true)

The code here is in charge of parsing the rules. It searches for `is` tiles and evaluates the rules. The first block evaluates horizontal rules and the second block evaluates vertical rules. The conditions before it **try to** make sure there are no overflows in the evaluation. For example, the horizontal check (marked with an orange rectangle) makes sure the `is` tile is not on the leftmost column, and the vertical rule (marked with a purple rectangle) makes sure the `is` tile is not on the first or last row.  
But, if you look closely, you can see that they are both just a little off and they give way to a little bit of a wiggle room:  
1. The horizontal rule doesn't check for `is` tiles being on the rightmost column
2. The vertial rule is off by 1 - it should check that the index of the tile is not `i >= 0xfc` but it checks `i > 0xfc`, which means that we can make it work on the bottom-left corner.

I always use the `tutori3l` level because it allows the most wiggle room:

!["is" failes!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/is_fails.png?raw=true)

Now, the first out of bounds is easy to understand - the map is stored in a continuous memory array, so it makes sense that the next tile after the rightmost column is at the leftmost column one row below. But in order to understand the 2 other ones, we need to dig a little deeper.  

My first instinct was that the access to map is made with modulus to the size of the map, and then it makes sense that accessing tile number 0x10e will just bring us to tile number 0. But there is something else entirely that is happening...  

In general, I don't like parsing assembly and badly-decompiled code - I always prefer cheats and helper tools. Analysing memory is one of those things I just really prefer doing. So without thinking too much I attached GDB to the `tas-emulator` process and dumped the heap. I figured since the memory of the Gameboy should be 8k, it makes sense that the emulator just malloc's it in the beginning and it should be continuous somewhere inside the heap, probably somewhere at the beginning.  
The simplest way I thought of to find where the map was, was taking one heap snapshot, moving `baba`, taking another snapshot and comparing the 2. I quickly found the map but it was a little different from what I expected to see:

![maps dump!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/maps.png?raw=true)

I highlighted the different sections in the memory view:
1. Green section - "first map" - what I found to be the map at address `0xc0b9` - what the function `get_tile_value` uses to get the tile value by index
2. Purple section - "second map" - what I found to be a complete copy of the first map at address `0xc1c7`. We'll get to that
3. Blue section - The index map

From first glance you can see that the first and second maps are exactly the same, but they differ from the map we found earlier in the ROM. They should start with
```
22 01 00 10 - wall  baba  is  you
```
but instead they start with
```
00 01 02 03
```
The index map, on the contrary, starts with the "correct" values `22 01 00 10`.  
Turns out the game doesn't store the actual tile types on the dynamic map in memory - it converts all elements to indexes in the `index map` and writes their values to the index map. I guess this makes it easier to change objects - if I create a rule that turns a wall into a door then the code just needs to go over the index map and turn all walls into doors, no matter where they are on the map. Ok, nice.  
This also explains our out of bounds bug - instead of accessing the first tile by means of wrap around or modulus, when we trigger the out of bounds the code actually accesses the **first tile of the second map**, but since it's exactly the same as the first map, it's the same as accessing the first map.  
Later I found that for all our intents and purposes the first and the second map are always the same, one of them is just used as a temporary map for a specific transformation that doesn't help us at all.  

We spent maybe hours trying to understand how the out of bounds bugs could help us solve this level but all failed since the first tile is just a wall character and can't be moved or assigned any attributes... We decided to look for another way.  
The index map is going to be relevant for a different level so keep that in mind.  

## Exploring further

The next area we looked at was the actual evaluation of the rules (the function I called `evaluate_is_block` at address `0x22dd`).  
It consists of 2 main areas:

!["is" evaluation!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/is_evaluation.png?raw=true)

The object assigment area is not very interesting, it's very straightforward. The attribute assignment, however, is very interesting - there is a LOT happening there. Let's digest!  
first of all, let's understand this:
```
puVar1 = (uchar *)CONCAT11(0xc3,g_num_rval_win + 3);
if (0xfc < g_num_rval_win) {
    puVar1 = (uchar *)CONCAT11(0xc4,g_num_rval_win + 3);
}
```
`g_num_rval_win` (address `0xc3b0`) is the number of assignments of the `win` attribute. Each time a `win` attribute is assigned, the `g_num_rval_win` value is increased by 1.  
The `CONCAT11` is basically making a short out of 2 bytes  
if `g_num_rval_win` is, say, `0` - then `puVar1` gets the value `0xc300 | (0+3) = 0xc303`  
if `g_num_rval_win` is `0xfd` - then `puVar1` gets the value `0xc400 | (0xfd+3) = 0xc400` remember that all the calculations are 8bit! so `0xfd + 3 = 0`!  
Ok cool, so all in all we have this:
```
char *puVar1 = 0xc303 + g_num_rval_win;
g_num_rval_win = g_num_rval_win + 1;
*puVar1 = l_obj;
```

I didn't explain what `l_obj` was:
```
l_obj = l_value + 0x20;
```
It just turns out that the value of each `Object` that represents a `Character` in the game is exactly the `Character + 0x20`. For example, `baba = 0x21` and the tile that represents `baba` is `0x01`.  
`l_value` is the input to this function - it's the value of the tile to the left (or to the top) of the `is` tile that is being evaluated.  

Ok, so we have a global array at 0xc303 that holds all the values that are assigned the `win` attribute. Let's get them all:
```
you:   0xc2fd
stop:  0xc300
win:   0xc303
open:  0xc306
close: 0xc309
death: 0xc30c
move:  0xc30f
```
There is something a little weird - the counters (`g_num_rval_win` etc.) are not confined to any value, but the arrays are all 3 bytes long... So if we manage to assign the same attribute to 4 different objects, the last one will **overflow into the next array!**. That could be interesting! But the only way to do that is to have 2 tiles with the same attribute on the map, and we don't have any...  
Or is it?  😏
There is actually a hint in a tutorial level about this:  

![close is stop!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/close_is_stop.png?raw=true)

I actually looked at this code and completely missed it... Thank god @gil was there to save the day. Let's look at how `close` and `stop` are evaluated here:  

![close is stop code!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/close_and_stop_code.png?raw=true)

**Close literally means stop!** So if we manage to assign 2 close and 2 stop attributes - the last close will overflow into the `win` array! That character will be considered the winning tile of the level! Is it possible in this level? Damn right it is!!  

![messin6 win!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/messin6_win.png?raw=true)

Let's read the relevant rules in the order of evaluation (looking for `is` blocks right to left, top to bottom):
1. Skull is stop
2. Key is close
3. Wall is stop
4. Door is close (overflow into `win`)

The door is now the win tile. Touch it and win :)

## Moving

I gotta say, that `missin6` level was the hardest one for me, I actually patched the game to skip it so we could figure out the solution for the next levels... And we arrived into `mov7ng`:  

![mov7ng!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mov7ng.png?raw=true)

Note that `baba is move` and `hxp is you` - we control the `hxp` tile and the `baba` tile is moving sideways. Moreover - it's moving to the left, pushing the only relevant tiles to the wall, leaving us with nothing to work with... But it was sufficient to play the level for 10 seconds to figure out what's happening - once the `baba` tile cannot move to the left anymore, it changes direction to the right. If at this point we die / restart the level - it will **start by moving to the right**. Easy.  

![mov7ng change direction!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mov7ng_change_dir.png?raw=true)

NEXT! We arrive to the next level (`c8llision`):

![c8llision!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/c8llision.png?raw=true)

The flag is moving to the left, we don't have any way to catch it and it dies when it hits the skull... Contrary to `mov7ng`, we can't make it change directions since it always dies and never reaches the end. We need to figure out how it determines where to move the first time the level starts.  
The relevant code was found in a function I called `process_user_input` at address `0x2bdb`. It moves all tiles that are assigned the `move` attribute and then the ones with the `you` attribute assigned. The function `move_tile_recursive` (address `0x26d5`) returns 0 if the tile failed to move (for example, was blocked, or movement direction was invalid)

![move code!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/move_code.png?raw=true)

I didn't even bother to check where that horrible address calculation takes us to, but my intuition said that it would be an array that corresponds to the index map and holds the last direction each index moved to. I checked it by taking a heap dump for the `mov7ng` level once when `baba` was moving right and once when it was moving left. `baba` is at index 6 for this level. The movement directions array is highlighted in red, the movement direction of `baba` is underlined in orange.  

![move dumps!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/move_dumps.png?raw=true)

The "bug" here is that the movement directions are not cleared on every lever start, so if at any point in the game there was an entity with our index that moved - the direction will be saved until the next moving element will get that index, and it will start moving in the direction that is written in that cell in the array.  
Ok, so we understand how the movement is calculated, but the flag in the `c8llision` level is at index 7, and throughout the game no tile at index 7 ever moved... This only works for tiles that were assigned the `move` ot `you` attributes... We can see that by looking at index 7 in the array, which holds 0. 0 is an illegal move, so when the game will try to move this tile - the `move_tile_recursive` function will return 0 and the default movement direction (left) will be assigned, and we lose.  
I searched for levels that could let me assign the `move` or `you` attribute to any tile at index 7 but failed... Until I got to the previous level (mov7ng) and then it hit me... The move tile is free, index 7 is a skull character and the skull object tile is free on the bottom! We can assign move to the skulls and force our skull to move right!  

![mov7ng index 7!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mov7ng_index_7.png?raw=true)

Now, it's important to say that the first movement of the skulls depends on everything you did in the previous levels. If you look at the movement direction array, you will notice that it's pretty random in terms of moves (1, 2, 4, 8 all over), so this state will be the first state that is evaluated when you click the next arrow button. For me it did something like that:  

![mov7ng index 7 first move!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/mov7ng_index_7_first_move.png?raw=true)

Which is chaotic but fine. Some skulls destroyed each other, but the most important one remained intact and was moving at full speed to the left. Now the only thing left to do is wait for it to reach the leftmost column, turn right and finish the level. If the flag gets destroyed in the middle by one of the skulls, that doesn't really matter since the direction has already beed saved in the array - you can restart the level and win normally. The flag will start moving to the right and you can catch it easily.  

## Rngesus

We have reached the last level!!!

![ran9om!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/ran9om.png?raw=true)

There is a random tile (hxp) - it takes random form (random attributes) and moves to a random direction so if we touch it when it randomly behaves like the win tile - we win.  
This is the level I spent the least time on as I just tried random stuff and figured out that every time i perform a certain move I win... The secret move is basically standing on the right of the hxp tile and quickly doing `up left down`:

![ran9om secret move!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/ran9om_secret_move.png?raw=true)

But I'll try to show why that works. When the `is` tile is being evaluated it's taking the right (or bottom) tile to understand what is the attribute/object it needs to assign to the left (or top) object tile. If the left tile is of the `random` type - it receives a random type using what i call the `fix_random_tile_value` function (address `0x23ef`):  

![random tile calculation!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/random_tile_calc.png?raw=true)

The values in these globals are set by the main loop (address `0x3158`):

![random values calculation!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/random_values_calc.png?raw=true)

The gist is that the byte at `0xc3a6` gets the user input (1=right, 2=left, 4=up, 8=down) and all the bytes get shifted one "right" (`0xc3a7` gets the value from `0xc3a6` etc.) the value from `0xc3ad` is discarded.

Now, this loop runs all the time, even if we don't supply any input - in that case our "input" is 0 and these global "random" values are zeroed out. When we press, for example, `up=4` then `0xc3a6` gets the value `4` and the next "frame" calculation this value will get pushed down the line all the way to `0xc3ad` and then discarded.  

What do we actually need to do though? We need to make the random tile return `win` to the rule applying function.  

The value for `random = 0x17` you can see that in the `fix_random_tile_value` function above.  
The value for `win = 0x11`.  
So in order to make the random tile return `win` we must have the values `2` and `4` in the random values array (`0xc3a6 - 0xc3ad`) since `0x17 ^ 2 ^ 4 = 0x11`. So we basically need to press `up` and `left` really quickly.  
But that's not enough - the moves are calculated **before** the rules - the `apply_rules` function is called from the `process_user_input` function at `0x2e0c`, and it's the very last thing that function does. So if our `left` move is the one touching the tile, we won't win. We need a "clean" left so the rules get calculated, the tile receives the `win` attriute, then we need to touch the tile and it doesn't really matter how.  
So we arrive close to the `hxp` tile, wait a little for the random array to clear, then quickly perform `up, left, down` and the `down` move touches the tile while it has the `win` attribute assigned.  

![flag!](https://github.com/amelkiy/write-ups/blob/master/hxp-2021/baba_is_you/pics/flag.png?raw=true)

## End

I created a text file containing all the moves and a script that generated the needed input for the program, but I found that the input I generate is not exactly aligned with the input receiving time... It's somewhere between 10 and 12 "frames", so I needed to tweak the moves a little bit, so if anyone is trying to read it (`moves.txt`) I'm sorry in advance 😁 but, instead, you can play the generated input file: `./tas-emulator playback moves.txt.bin`

The moves can be optimized by a LOT but, unfortunately, I didn't have time for it at all. But ALLES! did it in 396 moves!!! 😳 so try to beat that!

Hope you enjoyed my ~~novel~~ write up!
Pasten
