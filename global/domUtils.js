/**
 * Slightly fancier `document.createElement` that accepts attributes and children
 * 
 * @example
 * createElement("button", {class: ["unselectable", "warning-text"], "aria-label": "Remove domain"}, ["✕ ", createElement("span", {}, "Remove")]);
 *     // Result: `<button class="unselectable warning-text" aria-label="Remove domain">✕ <span>Remove</span></button>`
 * @example
 * // Note if both "className" and "class" are provided only the later-in-the-object value will be used, without warning:
 * createElement("div", {class: ["one", "two"], className: "three"});
 *     // Result: `<div class="three"></div>`
 * @example
 * // No whitespace is inserted between children:
 * createElement("span", {}, ["no", "spaces", createElement("em", {}, "added")]);
 *     // Result: `<span>nospaces<em>added</em></span>`
 * @param {string} tag The HTML tag to use
 * @param {Record<string, string|string[]>} [props] Attributes to set on the element. Classes can be passed in either `className` or `class`. Arrays will be space separated
 * @param {(Node|string) | (Node|string)[]} [contents] Both `Element`s and strings supported. Using type `Node` to also accept text nodes made with `createTextNode`
 * @returns {HTMLElement} A standard `Element` instance
 */
export function createElement(tag, props, contents) {
    const el = document.createElement(tag);

    if(props) {
        for(let p in props) {
            // Value stringification
            let value = props[p];
            if(Array.isArray(value)) value = value.join(' ');

            // "className" exception
            if(p === "className") p = "class";

            el.setAttribute(p, value);
        }
    }

    if(contents) {
        // Standardize format for spread operator
        const contentsArray = Array.isArray(contents)? contents : [contents];
        el.replaceChildren(...contentsArray);
    }

    return el;
}
