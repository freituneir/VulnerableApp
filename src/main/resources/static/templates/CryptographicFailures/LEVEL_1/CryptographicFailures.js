function setResult(element, message) {
  // Server text, rendered as text.
  element.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = message;
  element.appendChild(strong);
}

function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doGetAjaxCall(displayChallenge, url, true);
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

      let params = new URLSearchParams();
      params.append("password", password);

      doGetAjaxCall(appendResponseCallback, url + "?" + params.toString(), true);
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
