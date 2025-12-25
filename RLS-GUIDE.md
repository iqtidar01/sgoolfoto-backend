# Row-Level Security (RLS) Implementation Guide

## What is RLS?

Row-Level Security (RLS) allows you to filter data in Power BI reports based on the user viewing the report. Different users see different data based on their identity and roles.

## When to Use RLS

- **Multi-tenant applications**: Different customers see only their data
- **Regional filtering**: Sales reps see only their region's data
- **Department-based access**: HR sees HR data, Finance sees Finance data
- **User-specific data**: Each user sees only their own records

## How to Use

### Option 1: Without RLS (Default - All Users See Same Data)

```javascript
// Frontend call
const response = await axios.post('/api/embed-token', {
  reportId: 'your-report-id',
  datasetId: 'your-dataset-id'
});
```

### Option 2: With RLS (Users See Filtered Data)

```javascript
// Frontend call with user identity
const response = await axios.post('/api/embed-token', {
  reportId: 'your-report-id',
  datasetId: 'your-dataset-id',
  userIdentity: {
    username: 'user@company.com',  // User's email or identifier
    roles: ['SalesManager']         // Optional: RLS roles from Power BI
  }
});
```

## Setting Up RLS in Power BI

### Step 1: Define Roles in Power BI Desktop

1. Open your report in **Power BI Desktop**
2. Go to **Modeling** tab → **Manage Roles**
3. Click **Create** to add a new role (e.g., "SalesManager")
4. Add DAX filter expressions:

```dax
// Example: Filter by email
[UserEmail] = USERPRINCIPALNAME()

// Example: Filter by region
[Region] = "West"

// Example: Filter by user in a table
[SalesRep] = USERNAME()
```

5. Click **Save**

### Step 2: Test Roles in Power BI Desktop

1. Go to **Modeling** → **View as**
2. Select the role and enter a test user email
3. Verify the filtered data is correct

### Step 3: Publish to Power BI Service

1. **Publish** your report to Power BI Service
2. In Power BI Service, go to the **Dataset** → **Security**
3. Add users/groups to the roles you created

### Step 4: Use in Embed API

Now when you pass the `userIdentity` in your API call, Power BI will apply the role filters:

```javascript
userIdentity: {
  username: 'john.doe@company.com',
  roles: ['SalesManager']  // Must match role name in Power BI
}
```

## Complete Example

### Power BI Dataset Setup

Create a table `Users` with:
```
UserEmail        | Region | Department
-----------------+--------+------------
alice@co.com     | East   | Sales
bob@co.com       | West   | Sales
charlie@co.com   | East   | Finance
```

### Create RLS Role "RegionFilter"

DAX Expression:
```dax
[Region] = 
    LOOKUPVALUE(
        Users[Region],
        Users[UserEmail],
        USERPRINCIPALNAME()
    )
```

### Backend API Call

```javascript
// Alice only sees East region data
POST /api/embed-token
{
  "reportId": "abc-123",
  "datasetId": "def-456",
  "userIdentity": {
    "username": "alice@co.com",
    "roles": ["RegionFilter"]
  }
}
```

## Multiple Roles

You can assign multiple roles to a user:

```javascript
userIdentity: {
  username: 'manager@company.com',
  roles: ['RegionFilter', 'DepartmentFilter', 'ExecutiveView']
}
```

Power BI will apply **OR** logic - user sees data if they match ANY role.

## Dynamic RLS with Username

Use Power BI's built-in functions:

- `USERPRINCIPALNAME()` - Returns the username passed in the embed token
- `USERNAME()` - Same as USERPRINCIPALNAME() for embed scenarios

### Example DAX:

```dax
// Show only the user's own records
[Email] = USERPRINCIPALNAME()

// Or with a lookup table
LOOKUPVALUE(
    UserAccess[AllowedRegion],
    UserAccess[UserEmail],
    USERPRINCIPALNAME()
) = Sales[Region]
```

## Frontend Integration

Update your React component to pass user info:

```javascript
// PowerBIReport.js
const fetchEmbedToken = async () => {
  const response = await axios.post('/api/embed-token', {
    reportId,
    datasetId,
    userIdentity: {
      username: currentUser.email,  // From your auth system
      roles: currentUser.powerBiRoles // From your database
    }
  });
  // ... rest of code
};
```

## Security Best Practices

1. ✅ **Always validate user identity** on backend before passing to Power BI
2. ✅ **Never trust frontend** - user identity should come from authenticated session
3. ✅ **Use your auth system** - integrate with JWT, OAuth, etc.
4. ✅ **Test each role** - verify users only see their data
5. ✅ **Audit access** - log which users access which reports

## Common Issues

### Issue: User sees all data despite RLS

**Solution:**
- Verify role is assigned in Power BI Service dataset security
- Check DAX expression is correct
- Ensure username matches exactly (case-sensitive)
- Test role in Power BI Desktop first

### Issue: "Role not found" error

**Solution:**
- Role name in API call must exactly match role name in Power BI
- Role must be published with the dataset

### Issue: RLS works in Power BI Service but not in embed

**Solution:**
- Service Principal must have permission to generate tokens with identities
- In Power BI Admin Portal, enable "Service principals can use Power BI APIs"

## Advanced: Integrate with Authentication

```javascript
// Express middleware example
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = verifyJWT(token); // Your JWT verification
  req.user = user;
  next();
};

app.post('/api/embed-token', authenticate, async (req, res) => {
  const { reportId, datasetId } = req.body;
  
  // Get user info from authenticated session
  const userIdentity = {
    username: req.user.email,
    roles: req.user.powerBiRoles  // Stored in your database
  };
  
  const embedTokenData = await getEmbedToken(
    accessToken,
    reportId,
    [datasetId],
    userIdentity
  );
  
  res.json({ embedToken: embedTokenData.token });
});
```

## References

- [Power BI RLS Documentation](https://docs.microsoft.com/en-us/power-bi/admin/service-admin-rls)
- [Embed Token with RLS](https://docs.microsoft.com/en-us/rest/api/power-bi/embed-token/generate-token)
- [DAX Functions for RLS](https://docs.microsoft.com/en-us/dax/username-function-dax)

