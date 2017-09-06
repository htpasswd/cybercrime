javascript:(function(){
    if(localStorage["allLinks"] && localStorage.getItem("allLinks") !== ""){
        var allLinksArray = localStorage.getItem("allLinks").split("|");
    }else{
        var allLinksArray = [];
    }
    var newLinks = 0;
    var newUrl = '';
    
    var urls = document.querySelectorAll('h3.r a');
    for(i = 0; i < urls.length; i++){
        newUrl = urls[i].href;
        newUrl = newUrl.replace("http://", "").replace("https://", "");
        newUrl = newUrl.split("/")[0];

        if(findInArray(newUrl, allLinksArray) === "Unique"){
            allLinksArray.push(newUrl);
            newLinks += 1; 
        }
    }

    allLinksArrayLen = allLinksArray.length;
    tempAlert("<br><br><b>" + newLinks + "</b> added | " + allLinksArrayLen + " in total.", 5000);
    allLinksArray = allLinksArray.join("|");
    localStorage.setItem("allLinks", allLinksArray);

    if(document.getElementById('pnnext') !== null){
        var nextPage = document.getElementById('pnnext').href;
        window.location = nextPage;
    }else{
        tempAlert("<br><br><b>" + newLinks + "</b> added | " + allLinksArrayLen + " in total.<br><b>END OF SEARCH RESULTS</b>",5000,"red")
    }

function tempAlert(msg,duration, bcolor="green")
{
 var el = document.createElement("div");
 el.setAttribute("style","position:absolute;top:20%;left:20%;background-color:"+bcolor+";color:white;width:300px;height:300px;font-size:20px;text-align:center;vertical-align:middle");
 el.innerHTML = msg;
 setTimeout(function(){
  el.parentNode.removeChild(el);
 },duration);
 document.body.appendChild(el);
}

function findInArray(whatSearch, WhereToSearch){
        flagFound = "0";
        except = ["facebook.com", "wikipedia.org", "google.com"];
        whatSearch.replace(/^www\./, "");
        for(var z=0; z< WhereToSearch.length; z++){
        	WhereToSearch[z].replace(/^www\./, "");
            if(WhereToSearch[z] === whatSearch){
                flagFound = "1";
            }
        }
        for(var q=0; q< except.length; q++){
            if(except[q].indexOf(whatSearch) > -1){
                flagFound = "1";
            }
        }
        if(flagFound === "1"){
            return "Found";
        }else{
            return "Unique";
        }
    }

})();