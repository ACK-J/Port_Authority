let updating_storage = false;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getItemFromLocal(item, default_value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    const value_from_storage = await browser.storage.local.get({
        [item]: default_value,
    });
    updating_storage = false;
    try {
        return JSON.parse(value_from_storage[item]);
    } catch {
        return default_value;
    }
}

async function setItemInLocal(key, value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    await browser.storage.local.set({ [key]: JSON.stringify(value) });
    updating_storage = false;
    return;
}

async function handleClick(e) {
    if (e.target.dataset.action === "removeDomain" && e.target.dataset.domain) {
        const allowedDomainsList = await getItemFromLocal(
            "allowed_domain_list",
            []
        );
        const newAllowedDomainsList = allowedDomainsList.filter(
            (domain) => domain !== e.target.dataset.domain
        );
        await setItemInLocal("allowed_domain_list", newAllowedDomainsList);
        load_allowed_domains();
    }
}

async function load_allowed_domains() {
    // Remove the current event listener to avoid multiple event listeners
    if (
        document.querySelector("button").addEventListener("click", handleClick)
    ) {
        document
            .querySelector("button")
            .removeEventListener("click", handleClick);
    }

    document.querySelector("button").addEventListener("click", handleClick);
    const allowedDomainsList = await getItemFromLocal(
        "allowed_domain_list",
        []
    );

    const domainDomElements = allowedDomainsList.map((domain) => {
        const button = document.createElement("button");
        button.innerHTML = "Remove";
        button.dataset.domain = domain;
        button.dataset.action = "removeDomain";

        return `<li>${domain} ${button.outerHTML}</li>`;
    });

    const allowDomainsListDomElement = document.getElementById(
        "allowedDomainsListID"
    );
    allowDomainsListDomElement.innerHTML = domainDomElements.join("");
    allowDomainsListDomElement.addEventListener("click", handleClick);
}

async function saveOptions(e) {
    const allowed_domains_list = await getItemFromLocal(
        "allowed_domain_list",
        []
    );

    // We don't actually care about the protocol as we only compare url.host
    // But the URL object will fail to create if no protocol is provided
    let url = e.target[0].value + "";
    if (url.slice(0, 4) != "http") {
        url = "https://" + url;
    }
    try {
        const newUrl = new URL(url);
        const newUrlHost = newUrl.host;
        if (allowed_domains_list.indexOf(newUrlHost) !== -1) {
            alert("This domain is already in the list.");
            return;
        }
        allowed_domains_list.push(newUrlHost);
        await setItemInLocal("allowed_domain_list", allowed_domains_list);
    } catch (error) {
        console.error(error);
        alert("Please enter a valid domain.");
        return;
    }
}

load_allowed_domains();
document.querySelector("form").addEventListener("submit", saveOptions);
