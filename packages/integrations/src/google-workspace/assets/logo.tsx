import React, { SVGProps } from 'react';

export const Logo: React.FC<SVGProps<SVGSVGElement>> = (props) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={40}
      height={40}
      viewBox="0 0 40 40"
      {...props}
    >
      {/* Google "G" shield shape representing Workspace Admin */}
      <rect x="4" y="4" width="32" height="32" rx="4" fill="#4285F4" />
      <path
        d="M20 10c-5.52 0-10 4.48-10 10s4.48 10 10 10c5.52 0 10-4.48 10-10h-10v3.6h6.08c-0.72 3.36-3.72 5.84-7.28 5.04-3.52-0.8-5.84-4.24-5.04-7.76 0.64-2.84 3.04-5.04 5.92-5.44 1.92-0.28 3.76 0.32 5.16 1.52l2.68-2.68C25.28 11.6 22.76 10.4 20 10z"
        fill="white"
      />
    </svg>
  );
};
