window.fetch = new Proxy(window.fetch, {
    async apply(fetch, that, args) {
        // Forward function call to the original fetch
        data = args[1]
        // Do whatever you want with the resulting Promise

        api_url = "http://127.0.0.1:5555/add-parameter"
        original_url = window.location.href
        endpoint = args[0]
        data = args[1]
        body = {
          original_url:original_url,
          data:data,
          endpoint:endpoint
        }
        // Do whatever you want with the resulting Promise
        let fetchOptions = {
          //HTTP method set to POST.
          method: "POST",
          //Set the headers that specify you're sending a JSON body request and accepting JSON response
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          // POST request body as JSON string.
          body: body,
        };
        
        await fetch(api_url, fetchOptions);


        const result = fetch.apply(that, args);

        result.then((response) => {
            //console.log("fetch completed!", args, response);
        });

        return result;
    }
});
