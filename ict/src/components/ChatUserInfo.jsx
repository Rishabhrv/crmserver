import React from 'react'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faImages, faSpinner} from '@fortawesome/free-solid-svg-icons';
import imageIcon from './ImageIcon.jpg';


const ChatUserInfo = () => {
  return (
    <div className='w-70 p-3 pt-10 text-center'>
        <div className='flex items-center justify-center'>
            <h1 className='text-5xl bg-gray-100 rounded-full p-7 text-center'>PS</h1>
            
        </div>
        <h6 className='text-lg my-2 font-semibold text-gray-500'>Priyanshu Samanta</h6>
        <div className='flex my-3 border-b border-gray-200 pb-2'>
            <FontAwesomeIcon icon={faImages} className='text-gray-400 p-1 mr-1'/>
            <p className='text-gray-500'>Media & Docs</p>
        </div>

        <div className='border-b border-gray-200 pb-4'>
            <div className='flex gap-0'>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
            </div>
            <div className='flex gap-0'>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
                <img src={imageIcon} alt="Profile Icon" className="w-20 h-20 "/>
            </div>
        </div>

        <div className='flex my-5'>
            <FontAwesomeIcon icon={faSpinner} className='text-gray-300 text-2xl p-1'/>
            <div className='ml-2'>
                <p className='text-gray-900 text-sm'>Disappearing Messages </p>
                <p className='text-gray-500 text-left'>Off </p>
            </div>
        </div>
        



    </div>
  )
}

export default ChatUserInfo