# mali-metadata-field-auth

Base middleware utility for metadata auth field checks for Mali

[![npm version](https://img.shields.io/npm/v/mali-metadata-field-auth.svg?style=flat-square)](https://www.npmjs.com/package/mali-metadata-field-auth)
[![build status](https://img.shields.io/travis/malijs/metadata-field-auth/master.svg?style=flat-square)](https://travis-ci.org/malijs/metadata-field-auth)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg?style=flat-square)](https://standardjs.com)
[![License](https://img.shields.io/github/license/malijs/metadata-field-auth.svg?style=flat-square)](https://raw.githubusercontent.com/malijs/metadata-field-auth/master/LICENSE)

## API

<a name="module_mali-metadata-field-auth"></a>

### mali-metadata-field-auth
Generic Mali metadata field authorization middleware
If the call has metadata with "authorization" string property with <code>"{field} {value}"</code> then specified function is called.


| Param | Type | Description |
| --- | --- | --- |
| field | <code>String</code> | Field within the authorization metadata value to look for. |
| options | <code>Options</code> |  |
| options.error | <code>String</code> \| <code>Object</code> \| <code>function</code> | optional Error creation options.                                                If <code>String</code> the message for Error to throw in case                                                authorization is not present.                                                If <code>Object</code> the error options with <code>message</code>,                                                <code>code</code>, and <code>metadata</code> properties. See <code>create-grpc-error</code>                                                module.                                                If <code>Function</code> a function with signature <code>(ctx)</code>                                                called to create an error. Must return an <code>Error</code> instanse.                                                Default: <code>"Not Authorized"</code> |
| fn | <code>function</code> | The middleware function to execute with signature <code>(key, ctx, next)</code> |

**Example**  
```js
const fieldAuth = require('mali-metadata-field-auth')

app.use(fieldAuth('secret', async (key, ctx, next) => {
  console.log(key)
  await next()
})
```
## License

  Apache-2.0
