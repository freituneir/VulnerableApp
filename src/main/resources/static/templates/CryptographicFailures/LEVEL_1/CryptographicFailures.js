function setResult(element, message) {
  // Server text, rendered as text.
  element.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = message;
  element.appendChild(strong);
}

// The level endpoints answer POST only, so the description is fetched with an empty
// submission rather than a GET. Nothing about this request is sensitive; it is a POST
// purely because the endpoint no longer accepts a password in a URL.
function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doPostAjaxCall(displayChallenge, url, true, "", {
    "Content-Type": "application/x-www-form-urlencoded",
  });
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  // The server message is text: written through innerHTML it would be parsed as markup.
  challengeDiv.replaceChildren();
  const challengeText = document.createElement("strong");
  challengeText.textContent = data.content;
  challengeDiv.appendChild(challengeText);
  if (data.isValid) {
    challengeDiv.className = "challenge-secure";
  } else {
    challengeDiv.className = "challenge-vulnerable";
  }
}

function addingEventListenerToSubmitButton() {
  document
    .getElementById("submitButton")
    .addEventListener("click", function () {
      let url = getUrlForVulnerabilityLevel();
      let password = document.getElementById("password").value;

      if (!password) {
        let resultDiv = document.getElementById("result");
        setResult(resultDiv, "Please enter a password guess.");
        resultDiv.style.color = "red";
        return;
      }

      // The guess goes in the body. Appended to the URL it would be copied into access
      // logs, browser history and any outbound Referer header.
      let body = new URLSearchParams();
      body.append("password", password);

      doPostAjaxCall(appendResponseCallback, url, true, body.toString(), {
        "Content-Type": "application/x-www-form-urlencoded",
      });
    });
}

function appendResponseCallback(data) {
  let resultDiv = document.getElementById("result");
  if (data.isValid) {
    setResult(resultDiv, "Result: " + data.content);
    resultDiv.className = "result-success";
  } else {
    setResult(resultDiv, "Result: " + data.content);
    resultDiv.className = "result-failure";
  }
}

addingEventListenerToSubmitButton();
loadChallenge();
