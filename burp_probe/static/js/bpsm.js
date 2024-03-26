document.addEventListener("DOMContentLoaded", (event) => {
    document.body.addEventListener("htmx:beforeSwap", function(evt) {
        //if (evt.detail.xhr.status === 422) {
            evt.detail.shouldSwap = true;
            evt.detail.isError = false;
        //};
    });
});

htmx.onLoad(() => {
    htmx.findAll(".flash-message").forEach((element) => {
        if (!element.dying) {
            setTimeout(() => {
                element.addEventListener("animationend", () => {
                    element.remove();
                });
                element.classList.add("flash-message-hide");
            }, 5000);
            element.dying = true;
        };
    });
});
