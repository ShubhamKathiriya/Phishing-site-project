browser.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
  let tab = tabs[0];
  let url = tab.url;

    fetch(
      `https://immensely-solar-marlin-dynamo.wayscript.cloud/detect?URL=${url}`
    )
      .then((response) => response.json())
      .then((data) => {
        console.log(url)
        console.log(data)
        if(data.Safe)
        {
          document.getElementById("safe").innerHTML = "Site is Safe !!!";
        }
        else {
          document.getElementById("safe").innerHTML = "Site is not Safe !!!";
          document.getElementById("type").innerHTML = "Class is: " + data.Type;
        }
  
      });
}, console.error);