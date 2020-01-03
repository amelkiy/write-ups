WriteupBin is a web challenge - we are given a [source code](https://github.com/amelkiy/write-ups/blob/master/CCC/36c3/WriteupBin/WriteupBin-10b65573b511269f.tar.xz) of a website which hosts write-ups and a Dockerfile to build and run it.  
The website offers this functionlaity:
* Browse to the main page to get a unique ID (16 hex characters)
* You can write a write-up and submit it
* A submitted write-up gets a unique ID (16 hex characters)
* You can see a list of all YOUR write-ups and view each one of them. You can view a write-up which is not yours only if you have its ID
* You can like a write-up (yours or not, if you have the ID)
* You can "show your write-up to the admin" - the admin has an ID of "admin" and when you show him a write-up, he "likes" it  

More internal info:  
The write-ups are "validated" on client side by a JS package called [parsley](https://parsleyjs.org/). The validation makes sure there are no `<>` characters in the write-up.  
The way the admin is set up to like your write-up is by running a python script, which uses a Selenium driver to go the page of your write-up (`/show.php?id=GIVEN_ID`), find the like button with `find_element_by_xpath('//input[@id="like"]')` (finds the first element in the DOM with an id of `like`), and click that button.  
The flag is located in a random write-up by admin. This is also the only write-up the admin has. If we get the ID of this write-up we can view it and see the flag.

The first thing we did was to make sure we can inject HTML code into a write-up, and we could, since the validation only happens on client side. So our initial thought was that we can leak the flag using JS code or malicious `<style>` (using [this clever hack](https://hackaday.com/2018/02/25/css-steals-your-web-data/)) on the page when the admin browses to it, but we found that the CSP (Content Security Policy) was so strict that we couldn't inject any JS or CSS into the page.  

The next thing for us was to try to make the admin click on a button other than the original `like` button. The Selenium script finds the first `id=like` element in the DOM, so everything after the original `like` button is irrelevant. The injected HTML code in the write-up comes, of course, after the `like` button. So we started to search for a way to inject an HTML element before the `like` button and we discovered something useful:  
The [parsley](https://parsleyjs.org/) package is used to validate input elements in forms. It supports a custom message on validation error and, more importantly, it supports specifying a **custom HTML element to be a container for the error messages**. So if we somehow can invoke a parsley validation failure, we can try to inject a button with an `id=like` to the DOM before the original `like` button. We would need to do that before the Selenium searches for the button, which basically means on page `load`. So we tried this:
* Inject a form with a validated input, containing bad input
* Invoke validation on page load (tried various methods coupled with `autofocus`)
* Make the validation inject a `like` button to the bieginning of the DOM - we used the `<h3>` element as our container, as it's the only `h3` element in the page and it comes before the like button  

This is what we tried to inject:
```
<form data-parsley-validate>
	<input type="text" 
		data-parsley-trigger="load"
        data-parsley-required
        required

        data-parsley-errors-container="h3"
        data-parsley-error-message='<input type="button" id="like" value="CLICKME">'

        data-parsley-validate-if-empty
        data-parsley-validation-threshold="0"
        data-parsley-minlength="0"
        value=''
        autofocus>
	<input type="submit">
</form>
```
However, `load init blur focusin focusout` and all other valid triggers failed to validate on page load. *Later we found that other teams have been sucessful with `blur`, however, for some reason, we could not.*  
So we went to a slightly other direction - we found that we can invoke the validaton the moment the admin clicks the button (using the `focousout` trigger) - so we can inject something after the `click` but before the `submit`. Additionally, errors are getting injected **at the end of the error container**. We tried injecting a `hidden` input with `name=id value=1234` to the end of the like `<form>` and we discovered that it overrides the `id` that gets sent by the form to the admin. That means that **on validation failure we can make the admin like a write-up of our choosing**.  
If we could make the validation fail on a successful guess of the admin's write-up ID, we could use the `like` to mark a successful guess and try to guess the ID character by character. Lucky for us the parsley package supports a validation routine `data-parsley-equalto` which matches the data inside the `input` to another element in the DOM. The way this validation works is:
* The `input` element contains an attribute of `data-parsley-equalto="JQUERY_SELECTOR"`
* On validation, parsley finds the element by invoking `$(JQUERY_SELECTOR)`
* If the element is **found**, parsley checks that the data in the `input` is equal to `element.val()`
* If the element is **not found**, parsley checks that the data in the `input` is equal to the **value of the `data-parsley-equalto` attribute - JQUERY_SELECTOR**  

jQuery supports selecting elements by any attribute, and more importantly by partial match to an attribute, say, to the beginning of the value of an attribute. The write-up link in the admin's page is `<a href="/show.php?id=ID">` and we can select it by using this selector: `a[href^="/show.php?id=6"]`. If the ID starts with `6` then it will be selected, otherwise, no elements will be selected.  
So recap:
* We inject a `<form>` containing an `<input>` element with `data-parsley-equalto='a[href^="/show.php?id=6"]'` and `value='a[href^="/show.php?id=6"]'` - both values are identical
* The admin clicks on the like button and invokes the validation
* Parsley searches for this element: `a[href^="/show.php?id=6"]`
* If parsley doesn't find it, it matches the contents of the validated `input` to the selector string - validation **passes**. The admin likes the write-up
* If parsley finds it, it matces the contents of the validated `input` to `element.val()` - which **fails**, since the `a` element produces an empty string on `val()`.
* Since the validation fails, we inject an input to the like `<form>` which overwrites the `id input` in the `form` - The admin likes a write-up of our choosing  

The injected text:
```
<form data-parsley-validate>
	<input type="text" 
        data-parsley-trigger="focusout"
        data-parsley-equalto='a[href^="/show.php?id=GUESS"]'

        data-parsley-errors-container="form[action='/like.php']"
        data-parsley-error-message='<input type="input" name="id" value="0000000000000000">'

        value='a[href^="/show.php?id=GUESS"]'
        autofocus>
	<input type="submit">
</form>
```
We don't actually need the admin to like an actual post, we just need him **not to like ours** so we can use `value="0000000000000000"`.  
We loop for 16 characters and try to guess the ID of the flag character after character. Once we get the ID of the admin's write-up, we can view it and get the flag.  
The script that solves the challenge can be found [here](https://github.com/amelkiy/write-ups/blob/master/CCC/36c3/WriteupBin/solve.py)