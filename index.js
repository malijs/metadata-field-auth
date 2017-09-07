const auth = require('mali-metadata-auth')
const create = require('grpc-create-error')

/**
 * Generic Mali metadata field authorization middleware
 * If the call has metadata with "authorization" string property with <code>"{field} {value}"</code> then specified function is called.
 * @module mali-metadata-field-auth
 *
 * @param  {String} field Field within the authorization metadata value to look for.
 * @param  {Options} options
 * @param  {String|Object|Function} options.error optional Error creation options.
 *                                                If <code>String</code> the message for Error to throw in case
 *                                                authorization is not present.
 *                                                If <code>Object</code> the error options with <code>message</code>,
 *                                                <code>code</code>, and <code>metadata</code> properties. See <code>create-grpc-error</code>
 *                                                module.
 *                                                If <code>Function</code> a function with signature <code>(ctx)</code>
 *                                                called to create an error. Must return an <code>Error</code> instanse.
 *                                                Default: <code>"Not Authorized"</code>
 * @param  {Function} fn The middleware function to execute with signature <code>(key, ctx, next)</code>
 *
 * @example
 * const fieldAuth = require('mali-metadata-field-auth')
 *
 * app.use(fieldAuth('secret', async (key, ctx, next) => {
 *   console.log(key)
 *   await next()
 * })
 */
module.exports = function (field, options, fn) {
  if (!field || typeof field !== 'string') {
    throw new Error('field must be a string')
  }

  if (typeof options === 'function') {
    fn = options
    options = {}
  }

  let errFn = errorGenerator
  if (typeof options.error === 'string') {
    errFn = () => errorGenerator(options.error)
  } else if (typeof options.error === 'object') {
    errFn = () => create(options.error.message || 'Not Authorized', options.error.code, options.error.metadata)
  } else if (typeof options.error === 'function') {
    errFn = options.error
  }

  return auth(options, (authorization, ctx, next) => {
    if (!authorization) throw errFn()

    const parts = authorization.split(' ')
    if (parts.length !== 2) throw errFn()

    const scheme = parts[0]
    const credentials = parts[1]

    let key
    const rstr = String.raw`^${field}$`
    if (new RegExp(rstr, 'i').test(scheme)) {
      key = credentials
    }

    if (!key) throw errFn()

    return fn(key, ctx, next)
  })
}

function errorGenerator (message) {
  return new Error(message || 'Not Authorized')
}
