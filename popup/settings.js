let updating_storage = false;
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
async function getItemFromLocal(item, default_value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    const value_from_storage = await browser.storage.local.get({ [item]: default_value });
    updating_storage = false;
    return value_from_storage;
}

async function setItemInLocal(key, value) {
    while (updating_storage) {
        await sleep(500);
    }
    updating_storage = true;
    await browser.storage.local.set({ [key]: JSON.stringify(value) });
    updating_storage = false;
    console.log("final")
    return;
}

async function load_allowed_domains(){
    const allowed_domains_list_element = document.getElementById("allowedDomainsListID");

    const allowed_domains_object = await browser.storage.local.get("allowed_domain_list")
    const allowed_domains_string = allowed_domains_object['allowed_domain_list'];
    let allowed_domains_list = JSON.parse(allowed_domains_string);

    try {
        for (let domain = 0; domain < allowed_domains_list.length; domain++) {
            const domain_name = allowed_domains_list[domain];
            allowed_domains_list_element.innerHTML += domain_name + "<br />";
        }
    
    }
    // Something went wrong, empty the ul to be safe
    catch (error) {
        allowed_domains_list_element.innerHTML = "";
    }
}

async function saveOptions(e) {
    // https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
    let valid_domain = new RegExp("^(((?!\-))(xn\-\-)?[a-z0-9\-_]{0,61}[a-z0-9]{1,1}\.)*(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$", "i");
    // Make sure the user enters a valid domain name
    if (e.target[0].value.includes('.') && e.target[0].value.search(valid_domain) !== -1){

        // Get the list of allowed domains
        const allowed_domains_object = await getItemFromLocal("allowed_domain_list", []);
        const allowed_domains_string = allowed_domains_object['allowed_domain_list'];
        let allowed_domains_list = JSON.parse(allowed_domains_string);
        
        // Remove any leading "www."
        e.target[0].value = e.target[0].value.replace(/^(www\.)/,"");
        // If the domain doesn't exist in the list, add it
        if (allowed_domains_list.indexOf(e.target[0].value) === -1) {
            allowed_domains_list = allowed_domains_list.concat([e.target[0].value]);
            await setItemInLocal('allowed_domain_list', allowed_domains_list);
        }  
    }
  
  }
  
load_allowed_domains();
document.querySelector("form").addEventListener("submit", saveOptions);