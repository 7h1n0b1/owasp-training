// Fix the data.js file by escaping template expressions
const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'js', 'data.js');

try {
  // Read the file
  const fileContents = fs.readFileSync(filePath, 'utf8');
  
  // Find all occurrences of ${jndi inside template literals (between backticks) and escape them
  const fixedContents = fileContents.replace(/`([^`]*)\${jndi([^`]*)`/g, '`$1\\${jndi$2`');
  
  // Write the fixed content back to the file
  fs.writeFileSync(filePath, fixedContents);
  
  console.log('Successfully fixed data.js file by escaping template expressions');
} catch (err) {
  console.error('Error fixing data.js file:', err);
}