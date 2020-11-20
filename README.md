## My first acquaintance with Python.
The way I started to learn this language.

To run just use `python my-tests.py` or `python mass.py`

On the first run it may install these dependencies:

```
git
pip
nmap
Python-Requests
Python-httplib2
Python-xmltodict
Python-wget
```

Additionally it will clone these programs from its Github repositories:

```
SQLMap
WPScan
Nikto
Patator
w3af
OWASP ZAP
DSXS
```

Additionally it will instal dependencies of all the packages.


----
### Javascript scripts are the helpers for creating lists for mass checks.
`collectSQLiFromGoogle.js` - Is a bookmarklet that collects links with GET parameters parsed from Google.
To use it just add all the code from this bookmarlet instead of URL field when creating a bookmark in browser.
Then make a search request and click on the bookmark few times.

It will save all links that may have possibility to SQLi.

To show all the links use `showCollectedSQLi.js` bookmarklet.

You have to click it only on the same domain. All the links are saved in local storage that belongs to a certain domain.

To clear the local storage of links on a domain just use this bookmarklet:

```javascript
javascript:(function(){localStorage.setItem("allLinks", "");})();
```

----
To collect all domains from the search result use `collectAllDomains.js` bookmarklet.
To show the links use this bookmarklet:

```javascript
javascript:(function(){var allLinks=localStorage.getItem("allLinks").split("|");for(i=0;i<allLinks.length;i++){document.write(allLinks[i]+"<br>");}})();
```
