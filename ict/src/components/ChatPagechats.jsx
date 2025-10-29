import React from 'react'


const ChatPagechats = () => {
  return (
     <div className='ml-4'>
            <div className="flex items-center bg-white rounded-2xl shadow-sm px-3 py-2 w-74 mt-4">
                <svg
                    className="w-5 h-5 text-gray-400 mr-2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                >
                    <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z"
                    ></path>
                    </svg>
                    <input
                type="text"
                className="w-full outline-none text-gray-700 placeholder-gray-400"
            />
            </div>
    
            <div className='my-3 flex justify-between border-b border-gray-300 pb-2'>
                <div>
                    <button className='bg-gray-50 text-xs shadow-sm px-2 rounded-lg font-semibold text-gray-500'>New</button>
                    <button className='bg-gray-50 text-xs shadow-sm px-2 rounded-lg font-semibold text-gray-500 ml-2'>UnRead</button>
                </div>
                <div>
                    <button className='bg-gray-50 text-xs shadow-sm px-1 rounded-lg font-bold text-gray-500'>+</button>
                </div>
            </div>
    
            <div className='flex border-b border-gray-200 py-3'>
                <div className='bg-gray-200 p-2 rounded-full px-3'>
                    <h1 className='font-semibold text-gray-500 text-lg'>PS</h1>
                </div>
                <div className='p-1 pl-3'>
                    <h3 className='text-sm font-semibold text-gray-600'>Priyanshu Samanta</h3>
                    <p className='text-xs'>I want to message you.</p>
                </div>
            </div>

            <div className='flex border-b border-gray-200 py-3'>
                <div className='bg-gray-200 p-2 rounded-full px-3'>
                    <h1 className='font-semibold text-gray-500 text-lg'>PS</h1>
                </div>
                <div className='p-1 pl-3'>
                    <h3 className='text-sm font-semibold text-gray-600'>Priyanshu Samanta</h3>
                    <p className='text-xs'>I want to message you.</p>
                </div>
            </div>
            <div className='flex border-b border-gray-200 py-3'>
                <div className='bg-gray-200 p-2 rounded-full px-3'>
                    <h1 className='font-semibold text-gray-500 text-lg'>PS</h1>
                </div>
                <div className='p-1 pl-3'>
                    <h3 className='text-sm font-semibold text-gray-600'>Priyanshu Samanta</h3>
                    <p className='text-xs'>I want to message you.</p>
                </div>
            </div>
            <div className='flex border-b border-gray-200 py-3'>
                <div className='bg-gray-200 p-2 rounded-full px-3'>
                    <h1 className='font-semibold text-gray-500 text-lg'>PS</h1>
                </div>
                <div className='p-1 pl-3'>
                    <h3 className='text-sm font-semibold text-gray-600'>Priyanshu Samanta</h3>
                    <p className='text-xs'>I want to message you.</p>
                </div>
            </div>
    
            <div className='flex border-b border-gray-200 py-3'>
                <div className='bg-gray-200 p-2 rounded-full px-3'>
                    <h1 className='font-semibold text-gray-500 text-lg'>PS</h1>
                </div>
                <div className='p-1 pl-3'>
                    <h3 className='text-sm font-semibold text-gray-600'>Priyanshu Samanta</h3>
                    <p className='text-xs'>I want to message you.</p>
                </div>
            </div>
        </div>
  )
}

export default ChatPagechats