javascript: (function() {
    var allLinks = localStorage.getItem("allLinks").split("|");
    var allLinksLength = allLinks.length;
    var allLinksSorted = [];
    var uniqueLinks = [];
    var absoluteUniqueLinks = [];
    var mayBeRepeat = [];
    for(var h = 0; h < allLinksLength; h++){
        thisLinkPath = allLinks[h].split("?");
        thisLinkPathURL = thisLinkPath[0].replace(/(.*)\/.*/, "$1");
        thisLinkPars = thisLinkPath[1].replace(/=.*?&/g, "&").replace(/=.*/g, "");
        allLinksSorted.push([thisLinkPathURL+"?"+thisLinkPars, allLinks[h]])
    }

    allLinksSorted = allLinksSorted.sort();

    for(var i = 0; i < allLinksLength; i++){
        if(findInArray(allLinksSorted[i][0]) === "Same"){
            mayBeRepeat.push([allLinksSorted[i][0], allLinksSorted[i][1]]);
        }else{
            if(findInArray(allLinksSorted[i][0], 1) === "Absolute"){
                absoluteUniqueLinks.push([allLinksSorted[i][0], allLinksSorted[i][1]]);
            }else{
                uniqueLinks.push([allLinksSorted[i][0], allLinksSorted[i][1]]);
            }
        }
    }

    document.write("<br>-------- Absolutely Unique Links ("+absoluteUniqueLinks.length+") --------<br>");
    for(var a=0; a< absoluteUniqueLinks.length; a++){
        document.write(highlightUrl(absoluteUniqueLinks[a][1])+"<br>");
    }

    document.write("<br>-------- Unique Links ("+uniqueLinks.length+") --------<br>");
    for(var u=0; u< uniqueLinks.length; u++){
        document.write(highlightUrl(uniqueLinks[u][1])+"<br>");
    }
    document.write("<br>-------- May Be Repeated ("+mayBeRepeat.length+") --------<br>");
    for(var m=0; m< mayBeRepeat.length; m++){
        document.write("<font style='background-color:LightGray'>"+highlightUrl(mayBeRepeat[m][1])+"</font><br>");
    }

    window.stop();

    function highlightUrl(url){
        url = url.replace(/\?&/g, "?AmpersandAfterAskSign");
        linkSplit = url.split("?");
        linkUrl = linkSplit[0].replace(/(.*)\/(.*)/, "$1");
        linkPage = linkSplit[0].replace(/(.*)\/(.*)/, "$2");
        linkParams = linkSplit[1].replace(/^(.+?)=/g, "<b>$1</b>=").replace(/&(.+?)=/g, "&<b>$1</b>=").replace(/&(\w+)$/, "&<b>$1</b>").replace(/^(.+?)[^</b>]&/, "$1</b>&");
        linkParams = linkParams.replace(/<b>AmpersandAfterAskSign/g, "&<b>");
        return linkUrl+"/<font style='color:gray'>"+linkPage+"</font>"+"?"+linkParams;
    }

    function findInArray(whatSearch, absolute=0){
        flagFound = "0";
        if(absolute === 1){
            whatSearch = whatSearch.replace("//", "").replace(/(.*?)\/.*\?/, "$1");
            for(var z=0; z< absoluteUniqueLinks.length; z++){
                absoluteUniqueLinksAbs = absoluteUniqueLinks[z][0].replace("//", "").replace(/(.*?)\/.*\?/, "$1");
                if(absoluteUniqueLinksAbs === whatSearch){
                    flagFound = "1";
                }
            }
        }else{
            for(var z=0; z< uniqueLinks.length; z++){
                if(uniqueLinks[z][0] === whatSearch){
                    flagFound = "1";
                }
            }
        }
        if(flagFound === "1"){
            return "Same";
        }else if(flagFound === "0" && absolute === 1){
            return "Absolute";
        }else{
            return "Unique";
        }
    }
})();