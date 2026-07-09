(function () {
  function timezoneOptions() {
    if (typeof Intl.supportedValuesOf === "function") {
      return ["UTC"].concat(
        Intl.supportedValuesOf("timeZone").filter(function (zone) {
          return zone !== "UTC";
        })
      );
    }
    return ["UTC", "Europe/London", "Europe/Paris", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Asia/Tokyo", "Australia/Sydney"];
  }

  function populateSelectors() {
    document.querySelectorAll("[data-timezone-select]").forEach(function (select) {
      var selected = select.dataset.selectedTimezone || "UTC";
      var zones = timezoneOptions();
      if (zones.indexOf(selected) === -1) zones.unshift(selected);
      select.replaceChildren();
      zones.forEach(function (zone) {
        var option = document.createElement("option");
        option.value = zone;
        option.textContent = zone.replace(/_/g, " ");
        option.selected = zone === selected;
        select.appendChild(option);
      });
    });
  }

  function formatTimes(timezone) {
    document.querySelectorAll("[data-utc-time]").forEach(function (element) {
      var value = new Date(element.dataset.utcTime);
      if (Number.isNaN(value.getTime())) return;
      var format = element.dataset.timeFormat || "datetime";
      var options = format === "date"
        ? { year: "numeric", month: "2-digit", day: "2-digit" }
        : format === "friendly"
          ? { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }
          : { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: format === "minute" ? undefined : "2-digit", hourCycle: "h23" };
      options.timeZone = timezone;
      try {
        element.textContent = new Intl.DateTimeFormat(undefined, options).format(value);
        element.title = timezone;
      } catch (_) {
        element.title = "UTC";
      }
    });
  }

  populateSelectors();
  fetch("/api/site-timezone", { credentials: "same-origin" })
    .then(function (response) { return response.ok ? response.json() : { timezone: "UTC" }; })
    .then(function (data) { formatTimes(data.timezone || "UTC"); })
    .catch(function () { formatTimes("UTC"); });
})();
