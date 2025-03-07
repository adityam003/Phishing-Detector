// Check if we've already run
var hasRun = false;

// Listen for messages from popup
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.action === "checkStatus") {
        if (!hasRun) {
            // Run the analysis
            runPhishingDetection();
        }
        sendResponse({status: "received"});
    }
    return true;
});

function runPhishingDetection() {
    hasRun = true;

    var testdata = [
        isIPInURL(),
        isLongURL(),
        isTinyURL(),
        isAlphaNumericURL(),
        isRedirectingURL(),
        isHypenURL(),
        isMultiDomainURL(),
        isFaviconDomainUnidentical(),
        isIllegalHttpsURL(),
        isImgFromDifferentDomain(),
        isAnchorFromDifferentDomain(),
        isScLnkFromDifferentDomain(),
        isFormActionInvalid(),
        isMailToAvailable(),
        isStatusBarTampered(),
        isIframePresent()
    ];

    // Weights from the original script
    var weight = [3.33346292e-01, -1.11200396e-01, -7.77821806e-01, 1.11058590e-01,
                 3.89430647e-01, 1.99992062e+00, 4.44366975e-01, -2.77951957e-01,
                 -6.00531647e-05, 3.33200243e-01, 2.66644002e+00, 6.66735991e-01,
                 5.55496098e-01, 5.57022408e-02, 2.22225591e-01, -1.66678858e-01];

    var prediction = predict(testdata, weight);

    // Send the prediction and feature values back to the popup
    chrome.runtime.sendMessage({
        action: "phishingResult",
        prediction: prediction,
        features: testdata
    });
}

function predict(data, weight) {
    var f = 0;
    for (var j = 0; j < data.length; j++) {
        f += data[j] * weight[j];
    }
    return f > 0 ? 1 : -1;
}

// All the detection functions from the original script
function isIPInURL() {
    var reg = /\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
    var url = window.location.href;
    if (reg.exec(url) == null) {
        return -1;
    } else {
        return 1;
    }
}

function isLongURL() {
    var url = window.location.href;
    if (url.length < 54) {
        return -1;
    } else if (url.length >= 54 && url.length <= 75) {
        return 0;
    } else {
        return 1;
    }
}

function isTinyURL() {
    var url = window.location.href;
    if (url.length > 20) {
        return -1;
    } else {
        return 1;
    }
}

function isAlphaNumericURL() {
    var search = "@";
    var url = window.location.href;
    if (url.match(search) == null) {
        return -1;
    } else {
        return 1;
    }
}

function isRedirectingURL() {
    var reg1 = /^http:/;
    var reg2 = /^https:/;
    var srch = "//";
    var url = window.location.href;
    if (url.search(srch) == 5 && reg1.exec(url) != null && (url.substring(7)).match(srch) == null) {
        return -1;
    } else if (url.search(srch) == 6 && reg2.exec(url) != null && (url.substring(8)).match(srch) == null) {
        return -1;
    } else {
        return 1;
    }
}

function isHypenURL() {
    var reg = /[a-zA-Z]\//;
    var srch = "-";
    var url = window.location.href;
    if (((url.substring(0, url.search(reg) + 1)).match(srch)) == null) {
        return -1;
    } else {
        return 1;
    }
}

function isMultiDomainURL() {
    var reg = /[a-zA-Z]\//;
    var url = window.location.href;
    if ((url.substring(0, url.search(reg) + 1)).split('.').length < 5) {
        return -1;
    } else {
        return 1;
    }
}

function isFaviconDomainUnidentical() {
    var reg = /[a-zA-Z]\//;
    var url = window.location.href;
    if (document.querySelectorAll("link[rel*='shortcut icon']").length > 0) {
        var faviconurl = document.querySelectorAll("link[rel*='shortcut icon']")[0].href;
        if ((url.substring(0, url.search(reg) + 1)) == (faviconurl.substring(0, faviconurl.search(reg) + 1))) {
            return -1;
        } else {
            return 1;
        }
    } else {
        return -1;
    }
}

function isIllegalHttpsURL() {
    var srch1 = "//";
    var srch2 = "https";
    var url = window.location.href;
    if (((url.substring(url.search(srch1))).match(srch2)) == null) {
        return -1;
    } else {
        return 1;
    }
}

function isImgFromDifferentDomain() {
    var totalCount = document.querySelectorAll("img").length;
    var identicalCount = getIdenticalDomainCount("img");
    if (((totalCount - identicalCount) / totalCount) < 0.22) {
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.22) && (((totalCount - identicalCount) / totalCount) <= 0.61)) {
        return 0;
    } else {
        return 1;
    }
}

function isAnchorFromDifferentDomain() {
    var totalCount = document.querySelectorAll("a").length;
    var identicalCount = getIdenticalDomainCount("a");
    if (((totalCount - identicalCount) / totalCount) < 0.31) {
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.31) && (((totalCount - identicalCount) / totalCount) <= 0.67)) {
        return 0;
    } else {
        return 1;
    }
}

function isScLnkFromDifferentDomain() {
    var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length;
    var identicalCount = getIdenticalDomainCount("script") + getIdenticalDomainCount("link");
    if (((totalCount - identicalCount) / totalCount) < 0.17) {
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.17) && (((totalCount - identicalCount) / totalCount) <= 0.81)) {
        return 0;
    } else {
        return 1;
    }
}

function isFormActionInvalid() {
    var totalCount = document.querySelectorAll("form").length;
    var identicalCount = getIdenticalDomainCount("form");
    if (document.querySelectorAll('form[action]').length <= 0) {
        return -1;
    } else if (identicalCount != totalCount) {
        return 0;
    } else if (document.querySelectorAll('form[action*=""]').length > 0) {
        return 1;
    } else {
        return -1;
    }
}

function isMailToAvailable() {
    if (document.querySelectorAll('a[href^=mailto]').length <= 0) {
        return -1;
    } else {
        return 1;
    }
}

function isStatusBarTampered() {
    if ((document.querySelectorAll("a[onmouseover*='window.status']").length <= 0) || (document.querySelectorAll("a[onclick*='location.href']").length <= 0)) {
        return -1;
    } else {
        return 1;
    }
}

function isIframePresent() {
    if (document.querySelectorAll('iframe').length <= 0) {
        return -1;
    } else {
        return 1;
    }
}

function getIdenticalDomainCount(tag) {
    var i;
    var identicalCount = 0;
    var reg = /[a-zA-Z]\//;
    var url = window.location.href;
    var mainDomain = url.substring(0, url.search(reg) + 1);
    var nodeList = document.querySelectorAll(tag);
    if (tag == "img" || tag == "script") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].src;
            if (i && mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    } else if (tag == "form") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].action;
            if (i && mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    } else if (tag == "a") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].href;
            if (i && (mainDomain == (i.substring(0, i.search(reg) + 1))) && ((i.substring(0, i.search(reg) + 1)) != null) && ((i.substring(0, i.search(reg) + 1)) != "")) {
                identicalCount++;
            }
        });
    } else {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].href;
            if (i && mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    }
    return identicalCount;
}
