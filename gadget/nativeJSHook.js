(function (CONFIG) {
  let counter = 0;
  function report(functionName, value) {
    url = "http://localhost:8080/report-dom-xss";
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        functionName: functionName,
        index: counter,
        str: value,
        location: window.location.href,
      }),
    });
  }

  /**
   * Helper function to turn parsable arguments into nice strings
   * @arg {Object|string} arg Argument to be turned into a string
   **/
  function argToString(arg) {
    if (typeof arg === "string") return arg;
    if (typeof arg === "object") return JSON.stringify(arg);
    return arg.toString();
  }

  /**
   * Returns the type of an argument. Returns null if the argument should be
   * skipped.
   * @arg arg Argument to have it's type checked
   */
  function typeCheck(arg) {
    let knownTypes = [
      "function",
      "string",
      "number",
      "object",
      "undefined",
      "boolean",
      "symbol",
    ];
    let t = typeof arg;

    // sanity
    if (!knownTypes.includes(t)) {
      invalidArgType(args[i], +i, t);
      return t;
    }

    // configured to not check
    if (!CONFIG.types.includes(t)) {
      return null;
    }

    return t;
  }

  /**
   * Turn all arguments into strings and change record original type
   *
   * @args {Object} args `arugments` object of hooked function
   */
  function getArgs(args) {
    let ret = [];
    let hasInterest = 0;

    for (let i in args) {
      if (!args.hasOwnProperty(i)) continue;
      let t = typeCheck(args[i]);
      if (t === null) continue;
      let str = argToString(args[i]);

      ret.push({
        type: t,
        str: str,
        num: +i,
      });
    }
    return {
      args: ret,
      len: args.length,
    };
  }

  /**
   * Parse all arguments for function `name` and pretty print them in the console
   * @name {string} name Name of function that is being hooked
   * @args {Array}	args array of arguments
   **/
  function nativeJSHook(name, args) {
    let argObj = getArgs(args);
    if (argObj.args.length == 0) return;
    if (
      name == "set(Element.innerHTML)" ||
      name == "set(Element.outerHTML)" ||
      name == "document.write" ||
      name == "document.writeln"
    ) {
      for (let i = 0; i < argObj.args.length; i++) {
        let value = argObj.args[i].str;
        //const match = /<rid_[a-f0-9]{32}>/i.exec(value);
        report(name, value);
      }
    }
    counter = counter + 1;
  } // end nativeJSHook

  class ProxyHandler {
    apply(target, thisArg, args) {
      nativeJSHook(this.evname, args);
      return Reflect.apply(...arguments);
    }
    construct(target, args, newArg) {
      nativeJSHook(this.evname, args);
      return Reflect.construct(...arguments);
    }
  }

  /*
   * NOTICE:
   * updates here should maybe be reflected in input validation
   * file: /pages/config/config.js
   * function: validateFunctionsPattern
   */
  function applyHook(evname) {
    function getFunc(n) {
      let ret = {};
      ret.where = window;
      let groups = n.split(".");
      let i = 0; // outside for loop for a reason
      for (i = 0; i < groups.length - 1; i++) {
        ret.where = ret.where[groups[i]];
        if (!ret.where) {
          return null;
        }
      }
      ret.leaf = groups[i];
      return ret ? ret : null;
    }

    function hookErr(err, args, evname) {
      console.warn(
        "[EV] (%s) hook encountered an error: %s",
        evname,
        err.message
      );
      console.dir(args);
    }
    var ownprop = /^(set|value)\(([a-zA-Z.]+)\)\s*$/.exec(evname);
    let ep = new ProxyHandler();
    ep.evname = evname;
    if (ownprop) {
      let prop = ownprop[1];
      let f = getFunc(ownprop[2]);
      let orig = Object.getOwnPropertyDescriptor(f.where.prototype, f.leaf)[
        prop
      ];
      Object.defineProperty(f.where.prototype, f.leaf, {
        [prop]: new Proxy(orig, ep),
      });
    } else if (!/^[a-zA-Z.]+$/.test(evname)) {
      console.log("[EV] name: %s invalid, not hooking", evname);
    } else {
      let f = getFunc(evname);
      f.where[f.leaf] = new Proxy(f.where[f.leaf], ep);
    }
  }

  // grab console functions before hooking
  for (let name of CONFIG["functions"]) {
    applyHook(name);
  }
})({
  types: [
    "string",
    "object",
    "function",
    "number",
    "boolean",
    "undefined",
    "symbol",
  ],
  functions: [
    "eval",
    "Function",
    "set(Element.innerHTML)",
    "set(Element.outerHTML)",
    "value(Range.createContextualFragment)",
    "document.write",
    "document.writeln",
    "setInterval",
    "value(URLSearchParams.get)",
    "decodeURI",
  ],
});
