
const displayButton = document.getElementById("displayButton");

if (displayButton) {
  displayButton.addEventListener("click", () => {
    const userInput = document.getElementById("userInput");
    const safeOutput = document.getElementById("safeOutput");
    const xssStatus = document.getElementById("xssStatus");
    safeOutput.textContent = userInput.value;

    xssStatus.textContent =
      "Output displayed as text. HTML and scripts are not executed.";
  });
}

/* SecureWeb Shield: Security Events Viewer */
const eventList = document.getElementById("eventList");

if (eventList) {
  fetch("/events-data")
    .then((response) => {
      if (!response.ok) {
        throw new Error("Could not load security events.");
      }

      return response.json();
    })
    .then((events) => {
      eventList.textContent = "";

      if (events.length === 0) {
        eventList.textContent = "No security events recorded yet.";
        return;
      }

      events.forEach((event) => {
        const card = document.createElement("div");
        card.className = "event-card";

        const heading = document.createElement("h2");
        heading.textContent = event.event_type;

        const details = document.createElement("p");
        details.textContent = event.details || "No details available.";

        const time = document.createElement("small");
        time.textContent = event.created_at || "";

        card.append(heading, details, time);
        eventList.appendChild(card);
      });
    })
    .catch((error) => {
      eventList.textContent = error.message;
    });
}
