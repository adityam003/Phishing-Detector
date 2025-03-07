document.addEventListener('DOMContentLoaded', function() {
    const featuresToggle = document.getElementById('features-toggle');
    const featureList = document.getElementById('feature-list');

    // Toggle detection details
    featuresToggle.addEventListener('click', function() {
        featureList.classList.toggle('show');
        const icon = featuresToggle.querySelector('i');
        icon.classList.toggle('fa-chevron-down');
        icon.classList.toggle('fa-chevron-up');
    });

    // Show loading initially
    document.getElementById('loading').style.display = 'block';
    document.getElementById('content').style.display = 'none';

    // Define feature names
    const featureNames = {
        'isIPInURL': 'IP Address in URL',
        'isLongURL': 'Excessive URL Length',
        'isTinyURL': 'URL Shortening Service',
        'isAlphaNumericURL': 'Special Characters in URL',
        'isRedirectingURL': 'Redirecting URL',
        'isHypenURL': 'Hyphens in Domain',
        'isMultiDomainURL': 'Multiple Subdomains',
        'isFaviconDomainUnidentical': 'Mismatched Favicon',
        'isIllegalHttpsURL': 'HTTPS in Domain Part',
        'isImgFromDifferentDomain': 'Images from Different Domains',
        'isAnchorFromDifferentDomain': 'Links to Different Domains',
        'isScLnkFromDifferentDomain': 'Scripts/Links from Different Domains',
        'isFormActionInvalid': 'Invalid Form Actions',
        'isMailToAvailable': 'Mailto Links Present',
        'isStatusBarTampered': 'Status Bar Manipulation',
        'isIframePresent': 'Iframes Present'
    };

    // Get the current tab's URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        const url = currentTab.url;
        document.getElementById('current-url').textContent = url;

        // Check if content script is already injected
        chrome.tabs.sendMessage(currentTab.id, {action: "checkStatus"}, function(response) {
            // If we didn't get a response, the content script isn't injected yet
            if (chrome.runtime.lastError) {
                // Need to inject the content script
                chrome.tabs.executeScript(currentTab.id, {file: "jquery-3.1.1.min.js"}, function() {
                    chrome.tabs.executeScript(currentTab.id, {file: "content.js"}, function() {
                        // Now that content.js is injected, it will analyze and send results
                        console.log("Content script injected");
                    });
                });
            }
        });
    });

    // Listen for results from the content script
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        if (message.action === "phishingResult") {
            const prediction = message.prediction;
            const featureValues = message.features;

            // Update UI based on prediction
            updateResultUI(prediction);

            // Populate feature details
            populateFeatureList(featureValues);

            // Hide loading, show content
            document.getElementById('loading').style.display = 'none';
            document.getElementById('content').style.display = 'block';
        }
    });

    function updateResultUI(prediction) {
        const resultElement = document.getElementById('result');
        const resultIcon = document.getElementById('result-icon');
        const resultTitle = document.getElementById('result-title');
        const resultDescription = document.getElementById('result-description');

        if (prediction === 1) {
            // Phishing detected
            resultElement.classList.remove('safe');
            resultElement.classList.add('danger');
            resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle danger-icon"></i>';
            resultTitle.textContent = 'Warning: Phishing Detected!';
            resultDescription.textContent = 'This website exhibits characteristics commonly associated with phishing attacks.';
        } else {
            // No phishing detected
            resultElement.classList.remove('danger');
            resultElement.classList.add('safe');
            resultIcon.innerHTML = '<i class="fas fa-shield-alt safe-icon"></i>';
            resultTitle.textContent = 'Website Appears Safe';
            resultDescription.textContent = 'No phishing indicators were detected on this page.';
        }
    }

    function populateFeatureList(features) {
        const featureListElement = document.getElementById('feature-list');
        featureListElement.innerHTML = '';

        // Get feature names and values from the features array
        let featureIndex = 0;
        for (const featureName in featureNames) {
            if (featureIndex >= features.length) break;

            const value = features[featureIndex];
            const displayName = featureNames[featureName];

            // Create feature item
            const featureItem = document.createElement('div');
            featureItem.className = 'feature-item';

            // Create status icon based on value
            const statusIcon = document.createElement('div');
            statusIcon.className = 'feature-status';

            if (value === 1) {
                statusIcon.innerHTML = '<i class="fas fa-exclamation-circle status-danger"></i>';
                statusIcon.title = 'High Risk';
            } else if (value === 0) {
                statusIcon.innerHTML = '<i class="fas fa-exclamation-triangle status-warning"></i>';
                statusIcon.title = 'Medium Risk';
            } else {
                statusIcon.innerHTML = '<i class="fas fa-check-circle status-safe"></i>';
                statusIcon.title = 'Safe';
            }

            // Create feature name
            const featureNameElement = document.createElement('div');
            featureNameElement.className = 'feature-name';
            featureNameElement.textContent = displayName;

            // Append elements to feature item
            featureItem.appendChild(statusIcon);
            featureItem.appendChild(featureNameElement);

            // Append feature item to list
            featureListElement.appendChild(featureItem);

            featureIndex++;
        }
    }
});
