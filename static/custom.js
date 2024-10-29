document.addEventListener("DOMContentLoaded", () => {
    const phraseOutput = document.querySelector(".phrase-output"),
          phrases = [
              "carving exploits",
              "deploying dark web traps",
              "loading payloads in treat bags",
              "prepping disguise scripts",
              "tuning the fear firewall",
              "pinging ghost servers",
              "resurrecting forgotten exploits"
          ],
          phraseDelay = 1700,
          displayPhrases = () => {
              let delay = 0;
              phrases.forEach(phrase => {
                  setTimeout(() => phraseOutput.textContent = phrase, delay);
                  delay += phraseDelay;
              });
          };

    displayPhrases();

    setInterval(displayPhrases, (phrases.length * phraseDelay));
});