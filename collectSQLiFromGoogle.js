javascript:(function(){
    if(localStorage["allLinks"] && localStorage.getItem("allLinks") !== ""){
        var allLinksArray = localStorage.getItem("allLinks").split("|");
    }else{
        var allLinksArray = [];
    }
    var LinkFromArray = '';
    var LinkToArray = '';
    var addingFlag = 1;
    var newLinks = 0;
    var newUrl = '';
    var comparePars = '';
    
    var urls = document.querySelectorAll('h3.r a');
    for(i = 0; i < urls.length; i++){
        newUrl = urls[i].href;
        if(newUrl.indexOf('=') > -1 && newUrl.indexOf('?') > -1){
            addingFlag = 1;
            newUrlSplit = newUrl.split("?");
            LinkToArrayPATH = newUrlSplit[0];
            LinkToArrayPars = newUrlSplit[1].replace(/=.*?&/g, "&").replace(/=.*/g, "").split("&");
            LinkToArrayEXT = LinkToArrayPATH.substr(LinkToArrayPATH.length - 4).toLowerCase();
            if(allLinksArray.length > 0){
                for(a = 0; a < allLinksArray.length; a++){
                    arrayUrlSplit = allLinksArray[a].split("?");
                    LinkFromArrayPATH = arrayUrlSplit[0];
                    LinkFromArrayPars = arrayUrlSplit[1].replace(/=.*?&/g, "&").replace(/=.*/g, "").split("&");

                    if(LinkToArrayEXT === ".asp" || LinkToArrayEXT === "aspx"){
                        LinkToArrayPATH = LinkToArrayPATH.toLowerCase();
                        LinkFromArrayPATH = LinkFromArrayPATH.toLowerCase();
                    }

                    if(LinkFromArrayPATH.indexOf(LinkToArrayPATH) > -1){
                        comparePars = CompareArrays(LinkToArrayPars, LinkFromArrayPars);
                        
                        if(comparePars === "TheSame"){
                            addingFlag = 0;
                            break;
                        }
                        if(comparePars === "FirstHasMoreUnique"){
                            if(allLinksArray.indexOf(newUrl) > -1){
                                indexedPos = allLinksArray.indexOf(allLinksArray[a]);
                                allLinksArray = allLinksArray.splice(indexedPos, 1);
                                addingFlag = 0;
                            }else{
                                allLinksArray[a] = newUrl;
                                addingFlag = 0;
                            }
                        }
                        if(comparePars === "SecondHasMoreUnique"){
                            addingFlag = 0;
                        }
                    }
                }
            }
            if (addingFlag === 1){
                allLinksArray.push(newUrl);
                newLinks += 1;
            }
        }
    }

    allLinksArrayLen = allLinksArray.length;
    tempAlert("<br><br><b>" + newLinks + "</b> added | " + allLinksArrayLen + " in total.", 5000);
    allLinksArray = allLinksArray.sort();
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

function CompareArrays(CompareThis, ToThis){
    pairsCount = 0;
    for(z=0; z<CompareThis.length; z++){
        for(x=0; x<ToThis.length; x++){
            if(CompareThis[z] === ToThis[x]){
                pairsCount += 1;
            }
        }
    }
    if(pairsCount === CompareThis.length && pairsCount === ToThis.length){
        return "TheSame";
    }else{
        if(pairsCount === CompareThis.length && ToThis.length > pairsCount){
            return "SecondHasMoreUnique";
        }else if(pairsCount === ToThis.length && CompareThis.length > pairsCount){
            return "FirstHasMoreUnique";
        }else{
            return "Different";
        }
    }
}

})();